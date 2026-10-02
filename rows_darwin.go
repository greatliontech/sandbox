//go:build darwin

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// row is one rung of the ladder (docs/specs/sandbox.md, "Mechanism
// ladder") this backend delivers on darwin. The OS row is a Seatbelt
// profile applied by the platform's sandbox-exec: a filesystem
// allowlist and the network denied; the Minimal row is bounds
// alone, in the caller's own world, graded for nothing else. Neither
// row has namespaces: the kill tie is the process group on both, and
// darwin has no parent-death tie at all (docs/specs/sandbox.md, "No
// orphans").
type row struct {
	tier Isolation
}

var (
	osRow      = row{tier: OS}
	minimalRow = row{tier: Minimal}
)

// refuses names the intent in spec the row cannot deliver, if any.
// The OS row presents no hostname (no UTS namespace on this
// platform), and without a Root its profile allows the caller's
// whole world, under which a grant denied its writes is read-only
// only until an ancestor of it is renamed — Seatbelt matches the
// path of each operation as spelled at the time — so a read-only
// grant there has no rule that keeps it so, as on the Linux OS row.
// The Minimal row's mechanism set is bounds alone: it refuses every
// intent only a security boundary delivers — a Root, a hostname, a
// denied network, a read-only grant — and a Spec stating no limits,
// which would leave that row nothing to apply (docs/specs/sandbox.md,
// the ladder: sandbox never bare-execs).
func (r row) refuses(spec Spec) error {
	undeliverable := func(what string) error {
		return fmt.Errorf("%w: the %s row %s", ErrUndeliverable, r.tier, what)
	}
	if r.tier == OS {
		if spec.Hostname != "" {
			return undeliverable("presents no hostname")
		}
		if spec.Root == "" {
			for _, g := range spec.PathGrants {
				if g.Access == ReadOnly {
					return undeliverable(fmt.Sprintf("cannot make grant %s read-only without a Root: its profile then allows the whole world, and a renamed ancestor would carry the grant out of a deny rule", g.Path))
				}
			}
		}
		return nil
	}
	switch {
	case spec.Root != "":
		return undeliverable("cannot restrict the world to a Root")
	case spec.Hostname != "":
		return undeliverable("presents no hostname")
	case !spec.Network:
		return undeliverable("cannot deny the network: Network must be granted to run on it")
	}
	for _, g := range spec.PathGrants {
		if g.Access == ReadOnly {
			return undeliverable(fmt.Sprintf("cannot make grant %s read-only", g.Path))
		}
	}
	if spec.Limits == (Limits{}) {
		return undeliverable("applies bounds only, and none were stated: sandbox never bare-execs")
	}
	return nil
}

// hostFacts are the probed facts row selection reads: the reason
// the fact does not hold on this host, or nil where it does.
type hostFacts struct {
	// seatbelt: the platform's sandbox-exec is present and applies a
	// profile to this binary.
	seatbelt error
}

// selectRow picks the highest row whose facts hold and names, where
// a row is passed over, what fails for it. The OS row needs Seatbelt;
// the Minimal row always holds: rlimits and the watchdog are always
// there.
func selectRow(f hostFacts) (row, []string) {
	if f.seatbelt == nil {
		return osRow, nil
	}
	return minimalRow, []string{f.seatbelt.Error()}
}

// sandboxExec is the platform's profile applier: it compiles a
// profile, applies it to itself and execs the command in place, so
// the command runs under the profile at the same pid.
const sandboxExec = "/usr/bin/sandbox-exec"

// host caches the probed facts; hostOverride is the seam tests set to
// exercise every row on one host.
var (
	host         probeCache[hostFacts]
	hostOverride *hostFacts
)

func hostFactsFor(ctx context.Context) (hostFacts, error) {
	if hostOverride != nil {
		return *hostOverride, nil
	}
	return host.get(ctx, "", probeHost)
}

// probeHost asks the platform: sandbox-exec applying a profile that
// allows everything to this binary under the probe marker, which
// exits at once (runInit). A missing sandbox-exec, or one that cannot
// apply the profile (its own exit, with what it said), is the fact
// that the OS row is out of reach; the probe child dying otherwise is
// an anomaly, not an answer, as on every platform (docs/specs/
// sandbox.md, Re-exec).
func probeHost(ctx context.Context) (hostFacts, error) {
	var f hostFacts
	self, err := selfExecutable()
	if err != nil {
		return f, fmt.Errorf("sandbox: seatbelt probe: %w", err)
	}
	if _, err := os.Stat(sandboxExec); err != nil {
		f.seatbelt = fmt.Errorf("seatbelt: %s: %v", sandboxExec, err)
		return f, nil
	}
	cmd := exec.CommandContext(ctx, sandboxExec, "-p", "(version 1)(allow default)", self)
	cmd.Env = append(hostEnv(), envInit+"=1", envProbe+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return f, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if msg := strings.TrimSpace(string(out)); strings.HasPrefix(msg, "sandbox-exec:") {
			f.seatbelt = fmt.Errorf("seatbelt: %s", msg)
			return f, nil
		}
		return f, fmt.Errorf("sandbox: seatbelt probe: the re-exec'd init died (%v): a package init of this binary must not act under %s", err, envInit)
	}
	return f, fmt.Errorf("sandbox: seatbelt probe: %w", err)
}

// selfExecutable is this binary's path as the platform spells it,
// symlinks resolved: the profile allowlists it by that spelling, and
// Seatbelt matches canonical paths.
func selfExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// group is a run's process group by identity: the leader's pid,
// which is the group's id, and the leader's start time, which tells
// the run's leader from a later process the kernel hands the same
// pid once the group is gone. A pid is never reissued while a group
// with that id exists, so a group listed non-empty is the run's own
// unless its leader is a stranger by start time.
type group struct {
	pgid  int
	start unix.Timeval
}

// groupOf reads the group a leader starts.
func groupOf(leader *os.Process) (group, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", leader.Pid)
	if err != nil {
		return group{}, fmt.Errorf("sandbox: the run's leader: %w", err)
	}
	return group{pgid: leader.Pid, start: kp.Proc.P_starttime}, nil
}

// members lists the group's processes as the kernel has them, none
// where the group is gone or its id names a stranger's.
func (g group) members() ([]unix.KinfoProc, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", g.pgid)
	if err != nil {
		return nil, err
	}
	for _, p := range procs {
		if int(p.Proc.P_pid) == g.pgid && p.Proc.P_starttime != g.start {
			return nil, nil // the id reissued to another leader
		}
	}
	return procs, nil
}

// kill ends every member of the group, where the group is still the
// run's: the strongest kill this platform holds (docs/specs/
// sandbox.md, "No orphans"), which a payload can leave with setsid.
// What stays open is the window between the listing and the signal,
// in which the group could empty and its id be reissued to another
// leader — two adjacent syscalls wide, as on the Linux rows.
func (g group) kill() error {
	members, err := g.members()
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return nil
	}
	if err := syscall.Kill(-g.pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// sysProcAttr puts the run in a process group of its own, for the
// group kill to reach.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// exitWatch ends the group when its leader exits: a kqueue event on
// the leader's exit, which fires before the reap, so the zombie still
// pins the pid and the kill lands on the run's own group — and
// before the reap frees the pipes, so a descendant holding them
// cannot hold Wait open. The watch is registered while the init is
// blocked on its config, before anything has run; an exec never
// fires it, so the in-place execs to the applier, the second stage
// and the payload pass under it. A user event on the same queue
// wakes the goroutine for halt, which closes the queue only once the
// goroutine is done with its descriptor.
type exitWatch struct {
	kq   int
	done chan struct{}
}

// haltIdent is the user event's identity on the watch's queue.
const haltIdent = 1

func watchExit(g group) (*exitWatch, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("sandbox: exit watch: %w", err)
	}
	events := []unix.Kevent_t{
		{Ident: uint64(g.pgid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT},
		{Ident: haltIdent, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR},
	}
	if _, err := unix.Kevent(kq, events, nil, nil); err != nil {
		unix.Close(kq)
		return nil, fmt.Errorf("sandbox: exit watch: %w", err)
	}
	w := &exitWatch{kq: kq, done: make(chan struct{})}
	go func() {
		defer close(w.done)
		var out [1]unix.Kevent_t
		for {
			n, err := unix.Kevent(w.kq, nil, out[:], nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil || n == 0 {
				return
			}
			if out[0].Filter == unix.EVFILT_PROC {
				_ = g.kill()
			}
			return
		}
	}()
	return w, nil
}

// halt wakes the watch's goroutine, waits for it and closes the
// queue — never while the goroutine could still read it, so a
// descriptor number reissued to another watch is never read by this
// one.
func (w *exitWatch) halt() {
	if w == nil {
		return
	}
	trigger := []unix.Kevent_t{{Ident: haltIdent, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}}
	_, _ = unix.Kevent(w.kq, trigger, nil, nil)
	<-w.done
	unix.Close(w.kq)
}
