//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"

	"github.com/greatliontech/sandbox/internal/nslinux"
)

// row is one rung of the ladder (docs/specs/sandbox.md, "Mechanism
// ladder") this backend delivers on Linux. The Strong row is the
// namespaced world with its hardening; the Minimal row is bounds
// alone, in the caller's own namespaces, graded for nothing else. The
// OS row (Landlock) has no implementation here and is never selected
// (docs/issues/linux-os-row.md): a row with no mechanism to apply is
// not a row this host satisfies.
type row struct {
	tier Isolation
}

var (
	strongRow  = row{tier: Strong}
	minimalRow = row{tier: Minimal}
)

// groupKill reports whether the row's own kill tie is the process
// group — every row without a pid namespace. The clone puts such a
// run in a group of its own (sysProcAttr) and the kill addresses that
// group (killRun); both read this one predicate.
func (r row) groupKill() bool { return r.tier != Strong }

// refuses names the intent in spec the row cannot deliver, if any.
// The Minimal row's mechanism set is bounds alone: it refuses every
// intent only a security boundary delivers — a Root, which nothing
// would bound the world to; a hostname; a denied network; a read-only
// grant — and a Spec stating no limits, which would leave that row
// nothing to apply (docs/specs/sandbox.md, the ladder: sandbox never
// bare-execs).
func (r row) refuses(spec Spec) error {
	if r.tier != Minimal {
		return nil
	}
	undeliverable := func(what string) error {
		return fmt.Errorf("%w: the %s row %s", ErrUndeliverable, r.tier, what)
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
	// is known, so the row's arch guard kills as documented.
	seccompKill error
}

// selectRow picks the highest row whose facts hold for a spec that
// grants the network or not, and names, where the Strong row is
// passed over, what fails. The Minimal row always holds on Linux:
// rlimits are always there.
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
	return minimalRow, below
}

// probeCache holds once-per-process answers to host probes, keyed
// by what was probed. A probe's outcome is a fact for the process's
// lifetime — an anomaly included: a consumer init that breaches the
// re-exec contract breaches it every time — but a probe the caller's
// context ended is not an answer and is not remembered. Callers
// racing for the first answer wait on the lock, bounded by the
// prober's own deadline. A host that changes underneath a running
// caller is not modelled.
type probeCache[T any] struct {
	mu      sync.Mutex
	results map[string]probeResult[T]
}

type probeResult[T any] struct {
	value T
	err   error
}

func (c *probeCache[T]) get(ctx context.Context, key string, probe func(context.Context) (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.results == nil {
		c.results = map[string]probeResult[T]{}
	}
	if r, ok := c.results[key]; ok {
		return r.value, r.err
	}
	v, err := probe(ctx)
	if ctx.Err() != nil {
		var zero T
		return zero, ctx.Err()
	}
	c.results[key] = probeResult[T]{value: v, err: err}
	return v, err
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
// or restricted, ENOSPC where a namespace budget is exhausted, EINVAL
// or ENOSYS where a namespace type is not built.
var namespaceRefusals = []syscall.Errno{syscall.EPERM, syscall.ENOSPC, syscall.EINVAL, syscall.ENOSYS}

// probeHost asks the kernel: a clone of this binary into the Strong
// row's namespaces, the network namespace included; where that is
// refused, the same clone without the network namespace, since a
// kernel built without network namespaces refuses that flag alone;
// and the seccomp kill-process action.
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
	cmd.Env = append(os.Environ(), envInit+"=1", envProbe+"=1")
	cmd.SysProcAttr = attr
	err = cmd.Run()
	if err == nil {
		return nil, nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && slices.Contains(refusals, errno) {
		return errno, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil, fmt.Errorf("the re-exec'd init died (%v): a package init of this binary must not act under %s", err, envInit)
	}
	return nil, err
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
