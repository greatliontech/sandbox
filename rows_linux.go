//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"syscall"

	"github.com/greatliontech/sandbox/internal/nslinux"
)

// row is one rung of the ladder (docs/specs/sandbox.md, "Mechanism
// ladder") this backend delivers on Linux. The Strong row is the
// namespaced world with its hardening; the OS row, for a host that
// refuses namespaces, is a Landlock allowlist over the world at its
// host paths, the network denied by seccomp, no_new_privs, and
// static entrypoints only; the Minimal row is bounds alone, in the
// caller's own namespaces, graded for nothing else.
type row struct {
	tier Isolation
}

var (
	strongRow  = row{tier: Strong}
	osRow      = row{tier: OS}
	minimalRow = row{tier: Minimal}
)

// groupKill reports whether the row's own kill tie is the process
// group — every row without a pid namespace. The clone puts such a
// run in a group of its own (sysProcAttr) and the kill addresses that
// group (killRun); both read this one predicate.
func (r row) groupKill() bool { return r.tier != Strong }

// refuses names the intent in spec the row cannot deliver, if any.
// The OS row has no namespaces: it presents no hostname, and without
// a Root its allowlist is the caller's whole world, so a read-only
// grant there has no rule that could make it so — Landlock allows,
// never denies. The Minimal row's mechanism set is bounds alone: it
// refuses every intent only a security boundary delivers — a Root,
// which nothing would bound the world to; a hostname; a denied
// network; a read-only grant — and a Spec stating no limits, which
// would leave that row nothing to apply (docs/specs/sandbox.md, the
// ladder: sandbox never bare-execs).
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
					return undeliverable(fmt.Sprintf("cannot make grant %s read-only without a Root: its allowlist is then the whole world", g.Path))
				}
			}
		}
		return nil
	}
	if r.tier != Minimal {
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

// hostFacts are the probed facts row selection reads. Each holds the
// reason the fact does not hold on this host, or nil where it does.
type hostFacts struct {
	// namespaces: this process can create user, mount, pid, uts and
	// ipc namespaces with itself mapped as root.
	namespaces error
	// netns: a network namespace too — the one the Strong row needs
	// only for a spec that does not grant the network.
	netns error
	// seccompKill: seccomp filters exist and the kill-process action
	// is known, so a row's arch guard kills as documented.
	seccompKill error
	// landlock: the kernel exposes Landlock, at ABI landlockABI.
	landlock    error
	landlockABI int
}

// selectRow picks the highest row whose facts hold for a spec that
// grants the network or not, and names, where a row is passed over,
// what fails for it, in probe order. The Strong row needs the
// namespaces and the seccomp kill; the OS row needs Landlock and the
// seccomp kill; the Minimal row always holds on Linux: rlimits are
// always there.
func selectRow(f hostFacts, network bool) (row, []string) {
	var below []string
	if f.namespaces != nil {
		below = append(below, f.namespaces.Error())
	}
	if !network && f.netns != nil && f.namespaces == nil {
		// With every namespace refused, the network one adds nothing.
		below = append(below, f.netns.Error())
	}
	if f.seccompKill != nil {
		below = append(below, f.seccompKill.Error())
	}
	if len(below) == 0 {
		return strongRow, nil
	}
	if f.landlock != nil {
		below = append(below, f.landlock.Error())
	}
	if f.landlock == nil && f.seccompKill == nil {
		return osRow, below
	}
	return minimalRow, below
}

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

// namespaceRefusals are the kernel's answers that a namespace cannot
// be created: EPERM where unprivileged user namespaces are disabled
// or restricted by sysctl, EACCES where a security module restricts
// them — AppArmor's restriction of unprivileged user namespaces, on
// by default on Ubuntu 24.04, answers so — ENOSPC where a namespace
// budget is exhausted, EINVAL or ENOSYS where a namespace type is
// not built.
var namespaceRefusals = []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.ENOSPC, syscall.EINVAL, syscall.ENOSYS}

// probeHost asks the kernel: a clone of this binary into the Strong
// row's namespaces, the network namespace included; where that is
// refused, the same clone without the network namespace, since a
// kernel built without network namespaces refuses that flag alone;
// the seccomp kill-process action; and the Landlock ABI.
func probeHost(ctx context.Context) (hostFacts, error) {
	var f hostFacts
	refused, err := probeReexec(ctx, sysProcAttr(strongRow, false), namespaceRefusals...)
	if err != nil {
		return f, fmt.Errorf("sandbox: namespace probe: %w", err)
	}
	if refused != nil {
		f.netns = fmt.Errorf("network namespace: %w", refused)
		refused, err = probeReexec(ctx, sysProcAttr(strongRow, true), namespaceRefusals...)
		if err != nil {
			return f, fmt.Errorf("sandbox: namespace probe: %w", err)
		}
		if refused != nil {
			f.namespaces = fmt.Errorf("namespaces: %w", refused)
		}
	}
	f.seccompKill = nslinux.KillProcessAvailable()
	f.landlockABI, f.landlock = nslinux.LandlockABI()
	return f, nil
}

// probeReexec runs this binary as a probe child under attr — under
// the re-exec marker it exits at once (runInit) — and reports a
// kernel refusal from the listed errnos as refused. Any other failure
// is an anomaly, not an answer: the probe child is this binary under
// the re-exec marker, so its dying is the same contract breach as in
// the init proper (docs/specs/sandbox.md, Re-exec).
func probeReexec(ctx context.Context, attr *syscall.SysProcAttr, refusals ...syscall.Errno) (refused error, err error) {
	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Env = hostProbeEnv()
	cmd.SysProcAttr = attr
	err = cmd.Run()
	if err == nil {
		return nil, nil
	}
	if errno, ok := refusal(err, refusals); ok {
		return errno, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil, errors.New(initBreach("the re-exec'd init died", err))
	}
	return nil, err
}

// refusal is the kernel's refusal an error carries, where it carries
// one of the given: the errno beneath a failed clone, however wrapped.
func refusal(err error, refusals []syscall.Errno) (syscall.Errno, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) && slices.Contains(refusals, errno) {
		return errno, true
	}
	return 0, false
}

// killRun issues the strongest kill the run holds (docs/specs/
// sandbox.md, "No orphans"): the cgroup's kill where the run was
// placed in one — atomic over the subtree, unescapable — and then
// the row's own tie: on the Strong row the namespace's init, whose
// death takes the pid namespace with it; otherwise the process
// group, which a payload can leave with setsid.
//
// The group is addressed by the leader's pid, and a reaped leader's
// pid may already name another group — exec.Cmd's Wait can reap the
// leader before the context's cancel runs — so the leader is checked
// first through os.Process, which knows whether it was waited for,
// and the group is signalled only while the leader is known alive.
// That closes the interleaving exec makes likely. What stays open is
// two adjacent syscalls wide: a leader that exits by itself between
// the check and the signal leaves its pid held by any surviving
// member (a pid in use as a group id is not reissued), so the signal
// reaches exactly the run's survivors — but a leader that was the
// last member is freed at its reaping, and only then could its
// number name a new group before the signal lands. A failed cgroup
// kill is the error reported, never masked by the process being
// gone.
func killRun(r row, b bounds, p *os.Process) error {
	var cgErr error
	if b.cgroup != nil {
		cgErr = b.cgroup.Kill()
	}
	var err error
	if !r.groupKill() {
		err = p.Kill()
	} else if err = p.Signal(syscall.Signal(0)); err == nil {
		if kerr := syscall.Kill(-p.Pid, syscall.SIGKILL); kerr != nil && !errors.Is(kerr, syscall.ESRCH) {
			err = kerr
		}
	}
	if cgErr != nil {
		return fmt.Errorf("%w (process: %v)", cgErr, err)
	}
	return err
}

// sysProcAttr is the clone the row calls for: the Strong row's
// namespaces with the caller mapped as root, or a process group of
// the run's own for the group kill to reach. Either way the child
// dies with the caller (Pdeathsig), which on the Strong row is the
// namespace's init and so the whole namespace, and otherwise the
// direct child alone.
func sysProcAttr(r row, network bool) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if r.groupKill() {
		attr.Setpgid = true
		return attr
	}
	attr.Cloneflags = cloneFlags(network)
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	// GidMappingsEnableSetgroups defaults false → Go writes "deny"
	// to /proc/<pid>/setgroups, required for an unprivileged gid_map.
	return attr
}
