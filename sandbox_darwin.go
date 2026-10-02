//go:build darwin

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"unicode/utf8"

	"github.com/greatliontech/sandbox/internal/rlimit"
	"golang.org/x/sys/unix"
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

	outcome outcome // Wait's reaping memoized: Destroy waits too
}

// initConfig is the JSON payload handed to the re-exec'd init.
type initConfig struct {
	initCommon
	// Profile is the OS row's Seatbelt profile, applied by
	// sandbox-exec around the second stage; empty on the Minimal row.
	// Self is this binary at the kernel's spelling, the one the
	// profile admits and the applier execs.
	Profile string `json:"profile,omitempty"`
	Self    string `json:"self,omitempty"`
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
// entrypoint and working directory as the init sees them — under a
// Root, the host paths inside the tree — and the profile's
// ingredients: the tree, the grants and the rendezvous directory at
// the kernel's own spelling of their host paths.
type world struct {
	cmd     string
	workDir string
	root    string // the tree, the kernel's spelling; empty without one
	binds   []bind // targets the kernel's spelling
	runtime string // the rendezvous directory's target, the kernel's spelling
}

// resolveWorld checks, before anything runs, that every stated
// intent has somewhere to land on row r (docs/specs/sandbox.md,
// "Intent is portable; delivery is all-or-nothing"): the spelling
// checks, the row's own refusals, then the tree resolution every
// platform shares (resolveTree). Under a Root the OS row presents
// the tree at its host path (no mount namespace here either): the
// entrypoint and the working directory are their host paths inside
// the tree, and the entrypoint must load without the image-absolute
// layout the row does not present: a Mach-O image for this machine
// whose libraries are the platform's execution substrate or relative
// to the image (checkMachO). The profile matches the kernel's own
// spelling of a path — symlinks and firmlinks resolved, the
// filesystem's case — so the tree and the grants are read back so
// (kernelPath); containment and overlap the shared resolution judged
// by identity, where every spelling of one entry meets. Without a
// Root the world is the caller's whole: the entrypoint an
// executable file on the host.
func resolveWorld(spec Spec, r row) (world, error) {
	undeliverable := func(format string, a ...any) (world, error) {
		return world{}, fmt.Errorf("%w: "+format, append([]any{ErrUndeliverable}, a...)...)
	}
	if err := checkSpelling(spec); err != nil {
		return world{}, err
	}
	if err := r.refuses(spec); err != nil {
		return world{}, err
	}
	checkEntry := executableFile
	if spec.Root != "" {
		checkEntry = checkMachO
	}
	t, err := resolveTree(spec, checkEntry)
	if err != nil {
		return world{}, err
	}
	w := world{cmd: t.hostCmd, workDir: t.hostWorkDir}
	if t.root == "" {
		return w, nil
	}
	if w.root, err = kernelPath(t.root); err != nil {
		return undeliverable("root %s: %v", spec.Root, err)
	}
	for i, b := range t.binds {
		what := "grant"
		if i == t.runtime {
			what = "runtime dir"
		}
		if b.Target, err = kernelPath(b.Source); err != nil {
			return undeliverable("%s %s: %v", what, b.Source, err)
		}
		if i == t.runtime {
			w.runtime = b.Target
		}
		w.binds = append(w.binds, b)
	}
	return w, nil
}

// executableFile holds an entrypoint outside a Root to an executable
// file on the host.
func executableFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() || fi.Mode()&0o111 == 0 {
		return errors.New("is not an executable file")
	}
	return nil
}

// kernelPath is the kernel's own spelling of an existing path: what
// Seatbelt matches an operation's path against, read back from a
// descriptor opened for no access at all (O_EVTONLY) and without
// blocking (a FIFO opened for reading would wait for a writer).
func kernelPath(path string) (string, error) {
	return fcntlPath(path, unix.F_GETPATH)
}

// profile spells the OS row's Seatbelt profile. Without a Root: the
// caller's whole world, the network denied unless granted — unix
// sockets, reached by path, stay open as every row without
// namespaces leaves them (docs/specs/sandbox.md, "Root is
// world-restriction"); in SBPL the last rule matching an operation
// wins, so the unix-socket allowance follows the denial. Under a
// Root: nothing by default but the platform's execution substrate
// as Apple's own system.sb states it (dyld, the system libraries and
// frameworks, the services every process reaches), less the one
// place it lets a process create files (/cores); the tree read,
// mapped and executed, so an entrypoint may load the tree's own
// libraries and execute a sibling of the tree; this binary read and
// executed, the second stage running under the profile before the
// payload; each grant read, mapped and executed as on the Linux OS
// row, and written where read-write; the rendezvous directory read
// and written, unix sockets within it alone; the network, where
// granted, by address, with the platform's name resolution — a unix
// socket elsewhere on the host is not the network.
func profile(spec Spec, w world, self string) (string, error) {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	if w.root == "" {
		b.WriteString("(allow default)\n")
		if !spec.Network {
			b.WriteString("(deny network*)\n(allow network* (local unix-socket) (remote unix-socket))\n")
		}
		return b.String(), nil
	}
	root, err := sbplString(w.root)
	if err != nil {
		return "", err
	}
	selfQ, err := sbplString(self)
	if err != nil {
		return "", err
	}
	b.WriteString("(deny default)\n(import \"system.sb\")\n(deny file-write* (subpath \"/cores\"))\n")
	fmt.Fprintf(&b, "(allow process-exec file-map-executable (subpath %s) (literal %s))\n(allow process-fork)\n", root, selfQ)
	fmt.Fprintf(&b, "(allow file-read* (subpath %s) (literal %s))\n", root, selfQ)
	for _, g := range w.binds {
		if g.Target == w.runtime {
			continue
		}
		t, err := sbplString(g.Target)
		if err != nil {
			return "", err
		}
		if g.ReadOnly {
			fmt.Fprintf(&b, "(allow file-read* process-exec file-map-executable (subpath %s))\n", t)
		} else {
			fmt.Fprintf(&b, "(allow file-read* file-write* process-exec file-map-executable (subpath %s))\n", t)
		}
	}
	if w.runtime != "" {
		rt, err := sbplString(w.runtime)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "(allow file-read* file-write* (subpath %s))\n", rt)
		fmt.Fprintf(&b, "(allow network-bind (local unix-socket (subpath %s)))\n(allow network-inbound (local unix-socket (subpath %s)))\n(allow network-outbound (remote unix-socket (subpath %s)))\n", rt, rt, rt)
	}
	if spec.Network {
		// The network by address, and the platform's name resolution
		// with it: the resolver's daemon and its configuration, which
		// system.sb leaves out.
		b.WriteString("(allow network-outbound (remote ip))\n(allow network-inbound (local ip))\n(allow network-bind (local ip))\n")
		b.WriteString("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n(allow mach-lookup (global-name \"com.apple.dnssd.service\"))\n(allow file-read* (literal \"/private/var/run/resolv.conf\") (literal \"/private/etc/hosts\") (literal \"/private/etc/resolv.conf\"))\n")
	}
	return b.String(), nil
}

// sbplString quotes a path as an SBPL string: the quote and the
// backslash escaped, every other byte written as it is. A path
// holding a control character, or bytes that are no UTF-8, has no
// spelling the profile reader is known to take the same way, and is
// refused rather than spelled wrong.
func sbplString(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("path %q is not valid UTF-8", s)
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			return "", fmt.Errorf("path %q holds a control character", s)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
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
	s.group.Store(nil) // a failed start's group never serves the next
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
	self, err := selfExecutable()
	if err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	if self, err = kernelPath(self); err != nil {
		return fmt.Errorf("sandbox: this binary's path: %w", err)
	}
	cfg := initConfig{initCommon: initCommon{Row: r.tier.String(), WorkDir: w.workDir, Rlimits: b.rlimits, Cmd: w.cmd, Args: s.spec.Args, Env: payloadEnv(s.spec)}}
	if r.tier == OS {
		cfg.Self = self
		if cfg.Profile, err = profile(s.spec, w, self); err != nil {
			return fmt.Errorf("%w: %v", ErrUndeliverable, err)
		}
		if profileOverride != "" {
			cfg.Profile = profileOverride
		}
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
	cmd.Stdin = s.spec.Stdin
	cmd.Stdout = s.spec.Stdout
	cmd.Stderr = s.spec.Stderr
	// The group's identity is read, and the leader's exit watched,
	// while the init is certainly alive: it blocks on the config until
	// written. A failure here ends the init by the strongest tie read
	// so far (cmd.Cancel): the group's identity, or its pid, which it
	// still holds unreaped.
	var exited *exitWatch
	started := func() error {
		g, err := groupOf(cmd.Process)
		if err != nil {
			return err
		}
		s.group.Store(&g)
		exited, err = watchExit(g)
		if errors.Is(err, syscall.ESRCH) {
			// The init is already a zombie of ours — a package init
			// of this binary exited under the marker — which the
			// empty status pipe reports as the init's death
			// (startFailure); nothing is left to watch.
			exited, err = nil, nil
		}
		return err
	}
	// On every failure past the start the init is reaped by the
	// protocol, and the watch, which then fired on the init's own
	// exit at most, halted here.
	if err := startInit(ctx, r.tier, cmd, &cfg, started, func() { _ = cmd.Cancel() }); err != nil {
		exited.halt()
		return err
	}
	s.cmd, s.row, s.bounds, s.exited = cmd, r, b, exited
	if b.watch != nil {
		b.watch.start(*s.group.Load())
	}
	return nil
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
	if !s.outcome.begin() {
		return s.outcome.result()
	}
	status, err := reaped(s.cmd, s.cmd.Wait())
	s.exited.halt()
	if s.bounds.watch != nil {
		s.bounds.watch.halt()
	}
	_ = s.group.Load().kill()
	if s.bounds.watch != nil {
		if _, _, werr := s.bounds.watch.stats(); werr != nil && err == nil {
			err = werr
		}
	}
	s.outcome.end(status, err)
	return status, err
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
	if !s.outcome.ended() {
		_ = s.group.Load().kill()
	}
	_, err := s.Wait()
	return err
}

// Stats returns the run's accounting facts (docs/specs/sandbox.md,
// "Bounded means bounded"): the mechanism that enforced the bounds,
// and the watchdog's counters where it ran — the peak footprint it
// saw and its one kill, by the bound that made it.
func (s *darwinSandbox) Stats() (Stats, error) {
	if s.cmd == nil {
		return Stats{}, errors.New("sandbox: not started")
	}
	st := Stats{Accounting: s.bounds.accounting()}
	if s.bounds.watch != nil {
		peak, by, err := s.bounds.watch.stats()
		st.MemoryPeakBytes, st.MemoryKills, st.CPUKills, st.ProcessKills = peak, by.memory, by.cpu, by.procs
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
	if err := rlimit.Set(cfg.Rlimits); err != nil {
		return execPlan{}, intentError{fmt.Errorf("bound: %w", err)}
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
	return execPlan{
		Cmd:    sandboxExec,
		Args:   []string{"-p", cfg.Profile, cfg.Self},
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
