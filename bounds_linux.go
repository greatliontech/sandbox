//go:build linux

package sandbox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
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
		err := setMemoryMax(cg, l.MemoryBytes)
		unbounded, err := swapUnbounded(err, hierarchy.SwapPossible)
		if err != nil {
			_ = cg.Delete()
			return bounds{}, fmt.Errorf("sandbox: cgroup accounting: %w", err)
		}
		if unbounded {
			// The cgroup bounds memory but not the swap the process
			// could spill into: no whole bound, so no cgroup accounting
			// for this run — RLIMIT_AS caps the address space, swap
			// included. The cgroup this run will not use is released
			// here, and its release is the one on this path that a
			// run would otherwise never report.
			if derr := cg.Delete(); derr != nil {
				return bounds{}, fmt.Errorf("sandbox: cgroup accounting: releasing the cgroup left unused: %w", derr)
			}
			return fallback()
		}
	}
	b.pidsMax = l.MaxProcs
	b.cgroup = cg
	b.accounting = AccountingCgroups
	return b, nil
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

// setMemoryMax is the memory limit's verb; the one test that needs a
// kernel accounting no swap points it at one, since no host here can
// be made into one.
var setMemoryMax = (*nslinux.Cgroup).SetMemoryMax

// swapUnbounded reads a memory limit's outcome: a kernel that
// accounts no swap for the cgroup leaves the memory bound whole only
// where it can hold no swap at all (swapPossible false) — a fact
// that does not change under the run — and leaves it open otherwise,
// the process free to spill past the bound into whatever swap is or
// becomes live, in which case the cgroup is no accounting for the
// memory limit. Any other failure is a failure.
func swapUnbounded(err error, swapPossible func() bool) (bool, error) {
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, nslinux.ErrSwapUnaccounted) {
		return false, err
	}
	return swapPossible(), nil
}

// placements holds, per hierarchy, whether this host places a child
// into a cgroup at clone: a directory on the caller's ancestry
// accepts a cgroup with the controllers the bounds need, and the
// kernel clones into it (CLONE_INTO_CGROUP, kernel 5.7).
var placements probeCache[bool]

// placementSupported probes placement once per hierarchy: a probe
// cgroup, and a clone of this binary into it that exits at once under
// the probe marker (runInit). The probe runs under the caller's
// context — the wall clock is the caller's on every leg of Start —
// and the probe's controller enablement in an ancestor is permanent,
// as any Create's is. A probe child that exits at once makes the
// wait behind the cache's lock unobservable; only a consumer init
// that breaches the re-exec contract stretches it.
func placementSupported(ctx context.Context, hierarchy *nslinux.Hierarchy) (bool, error) {
	return placements.get(ctx, placementKey(hierarchy), func(ctx context.Context) (bool, error) { return probePlacement(ctx, hierarchy) })
}

// placementKey names a hierarchy in the placement cache.
func placementKey(hierarchy *nslinux.Hierarchy) string {
	return hierarchy.Root + "\x00" + hierarchy.ProcMounts + "\x00" + hierarchy.ProcSelfCgroup
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
	refused, err := probeReexec(ctx, &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}, syscall.ENOSYS, syscall.EOPNOTSUPP, syscall.EINVAL)
	if err != nil {
		return false, fmt.Errorf("placement probe: %w", err)
	}
	// A refusal means the kernel cannot clone into a cgroup: no
	// placement here.
	return refused == nil, nil
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
