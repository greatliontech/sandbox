//go:build linux

package sandbox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/greatliontech/sandbox/internal/nslinux"
)

// bounds is one run's resource accounting as selected for this host
// (docs/specs/sandbox.md, "Bounded means bounded"): the memory and
// process-count limits ride a cgroup the process is born into where
// the host affords placement and the controllers those limits need,
// and POSIX rlimits otherwise; the CPU-time and open-files limits are
// rlimits on either row, cgroup v2 having no equivalent cap. Which
// accounting enforced the memory and process bounds is reported, so
// a bound-exceeded death is attributable.
//
// The process-count bound is the one limit that must not take effect
// before exec: the init that composes the world is a multithreaded Go
// process, and a count that fits the payload does not fit the init.
// So the init applies it itself as its last act before exec — the
// pids.max of the cgroup it was born into (opened before the pivot
// takes the host view away, written after hardening), or
// RLIMIT_NPROC — while every other limit lands at clone or with the
// early rlimits.
type bounds struct {
	accounting Accounting
	cgroup     *nslinux.Cgroup  // nil under rlimits
	rlimits    []nslinux.Rlimit // applied early in the init
	late       []nslinux.Rlimit // applied by the init right before exec
	pidsMax    uint64           // written to the cgroup's pids.max right before exec
}

// selectBounds maps l onto the strongest accounting this host
// affords, creating the run's cgroup where it does. A stated limit is
// never dropped: where no cgroup can be placed — no directory on the
// caller's ancestry accepts one with the controllers, or the kernel
// cannot clone a child into one — the memory and process limits
// become rlimits; an anomaly of the hierarchy refuses rather than
// guessing.
func selectBounds(ctx context.Context, l Limits, hierarchy *nslinux.Hierarchy) (bounds, error) {
	b := bounds{accounting: AccountingNone}
	if l.CPUSeconds > 0 {
		b.rlimits = append(b.rlimits, nslinux.Rlimit{Resource: unix.RLIMIT_CPU, Cur: l.CPUSeconds, Max: l.CPUSeconds})
	}
	if l.MaxFiles > 0 {
		b.rlimits = append(b.rlimits, nslinux.Rlimit{Resource: unix.RLIMIT_NOFILE, Cur: l.MaxFiles, Max: l.MaxFiles})
	}
	if l.MemoryBytes == 0 && l.MaxProcs == 0 {
		if len(b.rlimits) > 0 {
			b.accounting = AccountingRlimits
		}
		return b, nil
	}
	fallback := func() (bounds, error) {
		if l.MemoryBytes > 0 {
			b.rlimits = append(b.rlimits, nslinux.Rlimit{Resource: unix.RLIMIT_AS, Cur: l.MemoryBytes, Max: l.MemoryBytes})
		}
		if l.MaxProcs > 0 {
			b.late = append(b.late, nslinux.Rlimit{Resource: unix.RLIMIT_NPROC, Cur: l.MaxProcs, Max: l.MaxProcs})
		}
		b.accounting = AccountingRlimits
		return b, nil
	}
	placed, err := placementSupported(ctx, hierarchy)
	if err != nil {
		return bounds{}, fmt.Errorf("sandbox: cgroup accounting: %w", err)
	}
	if !placed {
		return fallback()
	}
	var controllers []string
	if l.MemoryBytes > 0 {
		controllers = append(controllers, "memory")
	}
	if l.MaxProcs > 0 {
		controllers = append(controllers, "pids")
	}
	cg, err := hierarchy.Create(cgroupName("sandbox"), controllers)
	if errors.Is(err, nslinux.ErrNoAncestryBase) {
		return fallback()
	}
	if err != nil {
		return bounds{}, fmt.Errorf("sandbox: cgroup accounting: %w", err)
	}
	if l.MemoryBytes > 0 {
		if err := cg.SetMemoryMax(l.MemoryBytes); err != nil {
			_ = cg.Delete()
			return bounds{}, fmt.Errorf("sandbox: cgroup accounting: %w", err)
		}
	}
	b.pidsMax = l.MaxProcs
	b.cgroup = cg
	b.accounting = AccountingCgroups
	return b, nil
}

// placements holds, per hierarchy, the once-per-process answer to
// whether this host places a child into a cgroup at clone: a
// directory on the caller's ancestry accepts a cgroup with the
// controllers the bounds need, and the kernel clones into it
// (CLONE_INTO_CGROUP, kernel 5.7). Host facts for a process's
// lifetime; a host that changes underneath a running caller is not
// modelled. A probe the caller's context ended is not an answer and
// is not remembered.
var placements struct {
	mu   sync.Mutex
	byRt map[string]placementResult
}

type placementResult struct {
	ok  bool
	err error
}

// cgroupName names one cgroup this package creates — a run's, or a
// placement probe's — uniquely across processes: a random suffix
// beside the pid, so a predecessor killed at this pid with a cgroup
// still standing (a run cut short by SIGKILL, a probe between create
// and delete) never shadows the next one; a pid-and-counter name
// would collide exactly there. crypto/rand.Read never fails (a
// source failure is fatal to the process), so there is no degraded
// name.
func cgroupName(prefix string) string {
	var b [6]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s-%d-%x", prefix, os.Getpid(), b)
}

// placementSupported probes placement once per hierarchy: a probe
// cgroup, and a clone of this binary into it that exits at once under
// the probe marker (runInit). The probe runs under the caller's
// context — the wall clock is the caller's on every leg of Start —
// and the probe's controller enablement in an ancestor is permanent,
// as any Create's is. Callers racing for the first probe wait on its
// lock, bounded by the prober's own deadline; a probe that exits at
// once makes that wait unobservable, and only a consumer init that
// breaches the re-exec contract stretches it.
func placementSupported(ctx context.Context, hierarchy *nslinux.Hierarchy) (bool, error) {
	placements.mu.Lock()
	defer placements.mu.Unlock()
	if placements.byRt == nil {
		placements.byRt = map[string]placementResult{}
	}
	key := hierarchy.Root + "\x00" + hierarchy.ProcMounts + "\x00" + hierarchy.ProcSelfCgroup
	if r, ok := placements.byRt[key]; ok {
		return r.ok, r.err
	}
	ok, err := probePlacement(ctx, hierarchy)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	placements.byRt[key] = placementResult{ok: ok, err: err}
	return ok, err
}

func probePlacement(ctx context.Context, hierarchy *nslinux.Hierarchy) (bool, error) {
	mounted, err := hierarchy.Mounted()
	if err != nil || !mounted {
		return false, err
	}
	cg, err := hierarchy.Create(cgroupName(".placement"), []string{"memory", "pids"})
	if errors.Is(err, nslinux.ErrNoAncestryBase) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer cg.Delete()
	fd, err := cg.OpenFD()
	if err != nil {
		return false, err
	}
	defer fd.Close()
	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Env = append(os.Environ(), envInit+"=1", envProbe+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	err = cmd.Run()
	if err == nil {
		return true, nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.ENOSYS || errno == syscall.EOPNOTSUPP || errno == syscall.EINVAL) {
		// The kernel cannot clone into a cgroup: no placement here.
		return false, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		// The probe child is this binary under the re-exec marker; a
		// package init acting there is the same contract breach as in
		// the init proper (docs/specs/sandbox.md, Re-exec).
		return false, fmt.Errorf("placement probe: the re-exec'd init died (%v): a package init of this binary must not act under %s", err, envInit)
	}
	return false, fmt.Errorf("placement probe: %w", err)
}

// stats reads the run's accounting facts from the cgroup, or reports
// the mechanism alone where nothing counts.
func (b *bounds) stats() (Stats, error) {
	st := Stats{Accounting: b.accounting}
	if b.cgroup == nil {
		return st, nil
	}
	ct, err := b.cgroup.Counters()
	if err != nil {
		return st, err
	}
	st.MemoryPeakBytes = ct.MemoryPeak
	st.MemoryKills = ct.OOMKills
	st.ForksRefused = ct.ForksDenied
	return st, nil
}
