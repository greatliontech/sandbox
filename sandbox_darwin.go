//go:build darwin

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// darwinSandbox is the Seatbelt backend. Start re-execs the calling
// binary as the run's init (reexec.go): the init applies the bounds'
// rlimits to itself, enters the working directory and execs the
// platform's sandbox-exec with the row's profile, which applies the
// profile and execs the payload in place — one pid from the init to
// the payload — or, on the Minimal row, execs the payload itself.
// The run sits in a process group of its own, the kill tie this
// platform affords; the watchdog samples that group for the bounds
// the kernel will not hold (bounds_darwin.go).
type darwinSandbox struct {
	spec   Spec
	row    row // the row that ran; meaningful once cmd is set
	cmd    *exec.Cmd
	bounds bounds

	waited  bool // Wait's outcome is memoized: Destroy waits too
	status  ExitStatus
	waitErr error
}

// initConfig is the JSON payload handed to the re-exec'd init.
type initConfig struct {
	Row     string   `json:"row"`
	WorkDir string   `json:"workdir,omitempty"`
	Rlimits []rlimit `json:"rlimits,omitempty"`
	// Profile is the OS row's Seatbelt profile, applied by
	// sandbox-exec around the payload; empty on the Minimal row.
	Profile string   `json:"profile,omitempty"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env"`
}

func newSandbox(spec Spec) (Sandbox, error) {
	if spec.Exec == "" {
		return nil, errors.New("sandbox: Spec.Exec is required")
	}
	return &darwinSandbox{spec: spec}, nil
}

// selection is the one selection site: the host's facts and the row
// they reach, with what fails for the rows passed over. Start runs
// from it; reach reports it.
func selection(ctx context.Context) (row, []string, error) {
	facts, err := hostFactsFor(ctx)
	if err != nil {
		return row{}, nil, err
	}
	r, below := selectRow(facts)
	return r, below, nil
}

// reach is the selection reported: Reach's answer on darwin, which
// reads nothing of the spec — both rows run with the network granted
// or denied alike.
func reach(ctx context.Context, _ Spec) (Isolation, []string, error) {
	r, below, err := selection(ctx)
	if err != nil {
		return None, nil, err
	}
	return r.tier, below, nil
}

// Tier is the tier of the row that ran (docs/specs/sandbox.md, "Tier
// is derived"): None until Start has succeeded.
func (s *darwinSandbox) Tier() Isolation { return s.row.tier }

// world is the resolved shape of a run on this platform: the
// profile's ingredients at their canonical host paths, and the
// entrypoint and working directory as the init sees them.
type world struct {
	cmd      string
	workDir  string
	readOnly []string // read-only grants, canonical
}

// resolveWorld checks, before anything runs, that every stated
// intent has somewhere to land on row r (docs/specs/sandbox.md,
// "Intent is portable; delivery is all-or-nothing"). The row's own
// refusals come first. A stated Root is not yet delivered on this
// platform and is refused as such (docs/issues/darwin-root-world.md).
// Without a Root, the world is the caller's whole, the grants
// existing on the host; a read-only grant is the one intent the
// profile denies there.
func resolveWorld(spec Spec, r row) (world, error) {
	undeliverable := func(format string, a ...any) (world, error) {
		return world{}, fmt.Errorf("%w: "+format, append([]any{ErrUndeliverable}, a...)...)
	}
	if !filepath.IsAbs(spec.Exec) {
		return undeliverable("exec %q is not an absolute path", spec.Exec)
	}
	if spec.WorkDir != "" && !filepath.IsAbs(spec.WorkDir) {
		return undeliverable("workdir %q is not an absolute path", spec.WorkDir)
	}
	if len(spec.Hostname) > hostNameMax {
		return undeliverable("hostname %q is longer than %d bytes", spec.Hostname, hostNameMax)
	}
	if err := r.refuses(spec); err != nil {
		return world{}, err
	}
	if spec.Root != "" {
		return undeliverable("a Root is not yet delivered on this platform's %s row", r.tier)
	}
	w := world{cmd: spec.Exec, workDir: spec.WorkDir}
	if _, err := os.Stat(spec.Exec); err != nil {
		return undeliverable("exec %s: %v", spec.Exec, err)
	}
	for _, g := range spec.PathGrants {
		if !filepath.IsAbs(g.Path) || filepath.Clean(g.Path) != g.Path {
			return undeliverable("grant %q is not a clean absolute path", g.Path)
		}
		host, err := filepath.EvalSymlinks(g.Path)
		if err != nil {
			return undeliverable("grant %s: %v", g.Path, err)
		}
		if g.Access == ReadOnly {
			w.readOnly = append(w.readOnly, host)
		}
	}
	if spec.RuntimeDir != "" {
		if !filepath.IsAbs(spec.RuntimeDir) || filepath.Clean(spec.RuntimeDir) != spec.RuntimeDir {
			return undeliverable("runtime dir %q is not a clean absolute path", spec.RuntimeDir)
		}
		if fi, err := os.Stat(spec.RuntimeDir); err != nil {
			return undeliverable("runtime dir %s: %v", spec.RuntimeDir, err)
		} else if !fi.IsDir() {
			return undeliverable("runtime dir %s is not a directory", spec.RuntimeDir)
		}
	}
	return w, nil
}

// profile spells the OS row's Seatbelt profile for a world without a
// Root: the caller's whole world, the network denied unless granted
// — unix sockets, reached by path, stay open as every row without
// namespaces leaves them (docs/specs/sandbox.md, "Root is
// world-restriction") — and each read-only grant denied its writes
// throughout. Paths are quoted as SBPL strings.
func profile(spec Spec, w world) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")
	if !spec.Network {
		b.WriteString("(deny network*)\n(allow network* (local unix-socket) (remote unix-socket))\n")
	}
	for _, p := range w.readOnly {
		fmt.Fprintf(&b, "(deny file-write* (subpath %s))\n", sbplString(p))
	}
	return b.String()
}

// sbplString quotes a path for a profile: a Go-quoted string is one
// SBPL reads, its escapes the same.
func sbplString(s string) string { return strconv.Quote(s) }

// Start selects the row this host's facts satisfy, refuses below
// MinTier before anything runs, resolves the world and the bounds,
// and runs the init; it returns once the init has execed the row's
// applier or the payload, or with why it did not.
func (s *darwinSandbox) Start(ctx context.Context) error {
	if s.cmd != nil {
		return errors.New("sandbox: already started")
	}
	r, below, err := selection(ctx)
	if err != nil {
		return err
	}
	if r.tier < s.spec.MinTier {
		return &TierError{Reached: r.tier, Required: s.spec.MinTier, Lacking: below}
	}
	w, err := resolveWorld(s.spec, r)
	if err != nil {
		return err
	}
	b := selectBounds(s.spec.Limits)
	env := s.spec.Env
	if env == nil {
		env = hostEnv()
	}
	cfg := initConfig{
		Row:     r.tier.String(),
		WorkDir: w.workDir,
		Rlimits: b.rlimits,
		Cmd:     w.cmd,
		Args:    s.spec.Args,
		Env:     env,
	}
	if r.tier == OS {
		cfg.Profile = profile(s.spec, w)
	}
	self, err := selfExecutable()
	if err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("sandbox: config pipe: %w", err)
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		cfgR.Close()
		cfgW.Close()
		return fmt.Errorf("sandbox: status pipe: %w", err)
	}
	cmd := exec.CommandContext(ctx, self)
	// Cancellation kills by the strongest tie the run holds (killRun).
	cmd.Cancel = func() error { return killRun(cmd.Process) }
	cmd.SysProcAttr = sysProcAttr()
	cmd.Env = []string{envInit + "=1", envInitFD + "=3", envStatusFD + "=4"}
	cmd.ExtraFiles = []*os.File{cfgR, statusW}
	cmd.Stdin = s.spec.Stdin
	cmd.Stdout = s.spec.Stdout
	cmd.Stderr = s.spec.Stderr
	startErr := cmd.Start()
	if startErr != nil {
		cfgR.Close()
		cfgW.Close()
		statusR.Close()
		statusW.Close()
		return fmt.Errorf("sandbox: start: %w", startErr)
	}
	// The child holds its own copies; close ours so EOF can reach us.
	cfgR.Close()
	statusW.Close()
	encodeErr := json.NewEncoder(cfgW).Encode(&cfg)
	cfgW.Close()
	status, readErr := io.ReadAll(statusR)
	statusR.Close()
	if readErr != nil {
		_ = killRun(cmd.Process)
		cmd.Wait()
		return fmt.Errorf("sandbox: read init status: %w", readErr)
	}
	if encodeErr != nil {
		waitErr := cmd.Wait()
		return fmt.Errorf("sandbox: write init config: %v (init: %v)", encodeErr, waitErr)
	}
	outcome, reason := classifyStatus(status)
	if outcome == initExeced {
		s.cmd, s.row, s.bounds = cmd, r, b
		if b.watch != nil {
			b.watch.start(cmd.Process)
		}
		return nil
	}
	waitErr := cmd.Wait()
	return startFailure(r.tier, outcome, reason, status, ctx.Err(), waitErr)
}

// Wait reaps the process and reports how it ended, the watchdog
// halted first so its last sample is in the account. Wait is
// memoized: Destroy waits too, and a second call returns the first's
// outcome.
func (s *darwinSandbox) Wait() (ExitStatus, error) {
	if s.cmd == nil {
		return ExitStatus{}, errors.New("sandbox: not started")
	}
	if s.waited {
		return s.status, s.waitErr
	}
	s.waited = true
	err := s.cmd.Wait()
	if s.bounds.watch != nil {
		s.bounds.watch.halt()
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		s.status = ExitStatus{Code: 0}
	case errors.As(err, &exit):
		ws, ok := exit.Sys().(syscall.WaitStatus)
		if ok && ws.Signaled() {
			s.status = ExitStatus{Code: -1, Signaled: true, Signal: ws.Signal()}
		} else {
			s.status = ExitStatus{Code: exit.ExitCode()}
		}
	default:
		s.waitErr = err
	}
	return s.status, s.waitErr
}

// Signal sends a signal to the sandboxed process: sandbox-exec execs
// the payload in place, so the pid is the payload's.
func (s *darwinSandbox) Signal(sig os.Signal) error {
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("sandbox: not started")
	}
	return s.cmd.Process.Signal(sig)
}

// Destroy kills the run by the same tie as cancellation and reaps it.
func (s *darwinSandbox) Destroy() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	if !s.waited {
		_ = killRun(s.cmd.Process)
	}
	_, err := s.Wait()
	return err
}

// Stats returns the run's accounting facts (docs/specs/sandbox.md,
// "Bounded means bounded"): the mechanism that enforced the memory
// bound, and the watchdog's counters where it ran — the peak
// resident size it saw and the kills by the memory bound. A kill by
// the CPU bound is the exit's signal alone: the Stats carry no
// counter for it, a CPU-time death being the bound's on every row.
func (s *darwinSandbox) Stats() (Stats, error) {
	if s.cmd == nil {
		return Stats{}, errors.New("sandbox: not started")
	}
	st := Stats{Accounting: s.bounds.accounting(s.spec.Limits)}
	if s.bounds.watch != nil {
		st.MemoryPeakBytes, st.MemoryKills, _ = s.bounds.watch.stats()
	}
	return st, nil
}

// composeInit reads the config and composes the run on this platform:
// the bounds' rlimits applied to the init itself, which the exec
// hands on; the working directory entered; and the plan — the
// platform's sandbox-exec applying the profile around the payload on
// the OS row, the payload itself on the Minimal row.
func composeInit() (execPlan, error) {
	fdStr := os.Getenv(envInitFD)
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return execPlan{}, fmt.Errorf("bad %s=%q: %w", envInitFD, fdStr, err)
	}
	f := os.NewFile(uintptr(fd), "sandbox-config")
	if f == nil {
		return execPlan{}, fmt.Errorf("invalid config fd %d", fd)
	}
	var cfg initConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		f.Close()
		return execPlan{}, fmt.Errorf("decode config: %w", err)
	}
	f.Close()
	for _, l := range cfg.Rlimits {
		if err := syscall.Setrlimit(l.Resource, &syscall.Rlimit{Cur: l.Cur, Max: l.Max}); err != nil {
			return execPlan{}, intentError{fmt.Errorf("bound (rlimit %d=%d): %w", l.Resource, l.Cur, err)}
		}
	}
	if cfg.WorkDir != "" {
		if err := os.Chdir(cfg.WorkDir); err != nil {
			return execPlan{}, intentError{fmt.Errorf("chdir %s: %w", cfg.WorkDir, err)}
		}
	}
	if cfg.Profile == "" {
		return execPlan{Cmd: cfg.Cmd, Args: cfg.Args, Env: cfg.Env}, nil
	}
	return execPlan{Cmd: sandboxExec, Args: append([]string{"-p", cfg.Profile, cfg.Cmd}, cfg.Args...), Env: cfg.Env}, nil
}
