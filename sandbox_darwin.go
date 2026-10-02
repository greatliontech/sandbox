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
	"strings"
	"sync/atomic"
	"syscall"
)

// darwinSandbox is the Seatbelt backend. Start re-execs the calling
// binary as the run's init (reexec.go): the init applies the bounds'
// rlimits to itself, enters the working directory and, on the OS
// row, execs the platform's sandbox-exec with the row's profile,
// which applies the profile and execs this binary again as the
// second stage (runStage), which execs the payload in place — one
// pid from the init to the payload, the sentinel written only under
// the applied profile, so the applier's own failure is the row
// failing to apply and never the payload's exit; on the Minimal row
// the init execs the payload itself. The run sits in a process group
// of its own, the kill tie this platform affords; the watchdog
// samples that group for the bounds the kernel will not hold
// (bounds_darwin.go), and the group's remnants are ended when the
// payload exits, this platform having no namespace to take them.
type darwinSandbox struct {
	spec   Spec
	row    row // the row that ran; meaningful once cmd is set
	cmd    *exec.Cmd
	group  atomic.Pointer[group] // set once read, after the clone; nil until then
	exited *exitWatch
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
	// sandbox-exec around the second stage; empty on the Minimal row.
	Profile string   `json:"profile,omitempty"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env"`
}

// envPlan carries the payload's exec plan from the init to the second
// stage through the applier's environment — the init's own, never
// the payload's, which the plan holds.
const envPlan = "_SANDBOX_PLAN"

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
// entrypoint and working directory as the init sees them.
type world struct {
	cmd     string
	workDir string
}

// resolveWorld checks, before anything runs, that every stated
// intent has somewhere to land on row r (docs/specs/sandbox.md,
// "Intent is portable; delivery is all-or-nothing"). The row's own
// refusals come first. A stated Root is not yet delivered on this
// platform and is refused as such (docs/issues/darwin-root-world.md).
// Without a Root, the world is the caller's whole: the entrypoint an
// executable file on the host, the grants and the rendezvous
// directory existing there, read-write as they already are.
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
	fi, err := os.Stat(spec.Exec)
	if err != nil {
		return undeliverable("exec %s: %v", spec.Exec, err)
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return undeliverable("exec %s is not an executable file", spec.Exec)
	}
	for _, g := range spec.PathGrants {
		if !filepath.IsAbs(g.Path) || filepath.Clean(g.Path) != g.Path {
			return undeliverable("grant %q is not a clean absolute path", g.Path)
		}
		if _, err := os.Stat(g.Path); err != nil {
			return undeliverable("grant %s: %v", g.Path, err)
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
// world-restriction"); in SBPL the last rule matching an operation
// wins, so the unix-socket allowance follows the denial. The
// profile's rules name no path on this world.
func profile(spec Spec) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")
	if !spec.Network {
		b.WriteString("(deny network*)\n(allow network* (local unix-socket) (remote unix-socket))\n")
	}
	return b.String()
}

// profileOverride is the seam tests set to hand the applier a profile
// of their own.
var profileOverride string

// Start selects the row this host's facts satisfy, refuses below
// MinTier before anything runs, resolves the world and the bounds,
// and runs the init; it returns once the payload has been execed, or
// with why it was not.
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
		cfg.Profile = profile(s.spec)
		if profileOverride != "" {
			cfg.Profile = profileOverride
		}
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
	// Cancellation kills by the strongest tie the run holds: the
	// group, by its identity (group.kill) — or, before the identity
	// is read, by the leader's pid alone, which the unreaped init
	// still holds (os/exec stops watching the context at Wait).
	cmd.Cancel = func() error {
		if g := s.group.Load(); g != nil {
			return g.kill()
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
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
	// The group's identity is read, and the leader's exit watched,
	// while the init is certainly alive: it blocks on the config until
	// written. A failure here ends the init by its pid, which it
	// still holds unreaped.
	g, err := groupOf(cmd.Process)
	var exited *exitWatch
	if err == nil {
		s.group.Store(&g)
		exited, err = watchExit(g)
		if errors.Is(err, syscall.ESRCH) {
			// The init is already a zombie of ours — a package init
			// of this binary exited under the marker — which the
			// empty status pipe reports as the init's death below
			// (the config write failing for want of a reader read
			// the same way); nothing is left to watch.
			exited, err = nil, nil
		}
	}
	if err != nil {
		cfgW.Close()
		statusR.Close()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
		return err
	}
	encodeErr := json.NewEncoder(cfgW).Encode(&cfg)
	cfgW.Close()
	status, readErr := io.ReadAll(statusR)
	statusR.Close()
	// On every failure past this point the init is reaped and the
	// watch, which then fired on the init's own exit at most, halted.
	fail := func(err error) error {
		_ = g.kill()
		cmd.Wait()
		exited.halt()
		return err
	}
	if readErr != nil {
		return fail(fmt.Errorf("sandbox: read init status: %w", readErr))
	}
	// A config write refused for want of a reader is the init dead
	// before reading it, which the empty status pipe reports as the
	// death it is (startFailure); any other write failure is its own.
	if encodeErr != nil && !initUnread(encodeErr, status) {
		return fail(fmt.Errorf("sandbox: write init config: %v", encodeErr))
	}
	outcome, reason := classifyStatus(status)
	if outcome == initExeced {
		s.cmd, s.row, s.bounds, s.exited = cmd, r, b, exited
		if b.watch != nil {
			b.watch.start(g)
		}
		return nil
	}
	waitErr := cmd.Wait()
	exited.halt()
	return startFailure(r.tier, outcome, reason, status, ctx.Err(), waitErr)
}

// Wait reaps the payload and reports how it ended — a signal death
// with the code 128 plus the signal, as the Linux rows report it —
// the watchdog halted first so its last sample is in the account.
// The group's remnants are ended at the payload's exit by the exit
// watch (watchExit), before the reap, so a descendant holding the
// payload's pipes cannot hold Wait open; a descendant the payload
// left behind has no namespace to die with here and is not left to
// run on. A bound the watchdog could not hold is Wait's error. Wait
// is memoized: Destroy waits too, and a second call returns the
// first's outcome.
func (s *darwinSandbox) Wait() (ExitStatus, error) {
	if s.cmd == nil {
		return ExitStatus{}, errors.New("sandbox: not started")
	}
	if s.waited {
		return s.status, s.waitErr
	}
	s.waited = true
	err := s.cmd.Wait()
	s.exited.halt()
	if s.bounds.watch != nil {
		s.bounds.watch.halt()
	}
	_ = s.group.Load().kill()
	var exit *exec.ExitError
	switch {
	case err == nil:
		s.status = ExitStatus{Code: 0}
	case errors.As(err, &exit):
		ws, ok := exit.Sys().(syscall.WaitStatus)
		if ok && ws.Signaled() {
			s.status = ExitStatus{Code: 128 + int(ws.Signal()), Signaled: true, Signal: ws.Signal()}
		} else {
			s.status = ExitStatus{Code: exit.ExitCode()}
		}
	default:
		s.waitErr = err
	}
	if s.bounds.watch != nil {
		if _, _, werr := s.bounds.watch.stats(); werr != nil && s.waitErr == nil {
			s.waitErr = werr
		}
	}
	return s.status, s.waitErr
}

// Signal sends a signal to the sandboxed process: the applier and
// the second stage exec in place, so the pid is the payload's.
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
		_ = s.group.Load().kill()
	}
	_, err := s.Wait()
	return err
}

// Stats returns the run's accounting facts (docs/specs/sandbox.md,
// "Bounded means bounded"): the mechanism that enforced the bounds,
// and the watchdog's counters where it ran — the peak resident size
// it saw and its kill by the memory bound. A kill by the CPU or the
// process bound is the exit's signal alone: the Stats carry no
// counter for those.
func (s *darwinSandbox) Stats() (Stats, error) {
	if s.cmd == nil {
		return Stats{}, errors.New("sandbox: not started")
	}
	st := Stats{Accounting: s.bounds.accounting()}
	if s.bounds.watch != nil {
		var err error
		st.MemoryPeakBytes, st.MemoryKills, err = s.bounds.watch.stats()
		if err != nil {
			return st, err
		}
	}
	return st, nil
}

// composeInit reads the config and composes the run on this platform:
// the bounds' rlimits applied to the init itself, which the exec
// hands on; the working directory entered; and the plan — the
// platform's sandbox-exec applying the profile around this binary's
// second stage on the OS row, the payload's plan carried to it
// through the applier's environment; the payload itself on the
// Minimal row.
func composeInit() (execPlan, error) {
	cfg, err := readInitConfig[initConfig]()
	if err != nil {
		return execPlan{}, err
	}
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
	payload := execPlan{Cmd: cfg.Cmd, Args: cfg.Args, Env: cfg.Env}
	if cfg.Profile == "" {
		return payload, nil
	}
	plan, err := json.Marshal(payload)
	if err != nil {
		return execPlan{}, fmt.Errorf("encode the second stage's plan: %w", err)
	}
	self, err := selfExecutable()
	if err != nil {
		return execPlan{}, err
	}
	return execPlan{
		Cmd:    sandboxExec,
		Args:   []string{"-p", cfg.Profile, self},
		Env:    []string{envInit + "=2", envStatusFD + "=" + os.Getenv(envStatusFD), envPlan + "=" + string(plan)},
		Staged: true,
	}, nil
}

// runStage is the second stage, this binary under the applied
// profile: it reads the payload's plan from the applier's
// environment and execs it, the sentinel written first
// (execPayload).
func runStage() {
	status := statusPipe()
	if status != nil {
		if _, err := status.WriteString(statusStaged); err != nil {
			fmt.Fprintln(os.Stderr, "sandbox-init: status pipe:", err)
			os.Exit(127)
		}
	}
	var plan execPlan
	if err := json.Unmarshal([]byte(os.Getenv(envPlan)), &plan); err != nil {
		msg := statusApplyFailed + fmt.Sprintf("decode the second stage's plan: %v", err)
		if status != nil {
			status.WriteString(msg)
			status.Close()
		} else {
			fmt.Fprintln(os.Stderr, "sandbox-init:", msg)
		}
		os.Exit(127)
	}
	execPayload(status, plan)
}
