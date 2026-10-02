//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rlimit is one resource limit the init applies to itself before the
// exec, which the payload inherits.
type rlimit struct {
	Resource int    `json:"resource"`
	Cur      uint64 `json:"cur"`
	Max      uint64 `json:"max"`
}

// bounds are the run's limits as this platform delivers them (docs/
// specs/sandbox.md, "Bounded means bounded"): the kernel's rlimits
// where it enforces them — CPU time, which it delivers as SIGXCPU at
// the limit; open files; processes, counted per user — and, where it
// has no native bound an unprivileged process can set, the watchdog:
// the kernel refuses every memory rlimit (RLIMIT_AS, RLIMIT_DATA,
// RLIMIT_RSS answer EINVAL) and its per-task memory limit to all but
// root, and a payload that handles SIGXCPU outlives the CPU limit,
// so memory and CPU are bounded by sampling the kernel's own
// per-process readings over the run's process group and killing the
// group at the bound.
type bounds struct {
	rlimits []rlimit
	watch   *watchdog
}

// watchInterval paces the watchdog: the bound is exceeded by at most
// what the group can take in one interval, and a hundred samples a
// second cost the host a fraction of a percent of one core.
const watchInterval = 10 * time.Millisecond

// selectBounds maps the limits to the platform's accounting.
func selectBounds(l Limits) bounds {
	var b bounds
	if l.CPUSeconds > 0 {
		b.rlimits = append(b.rlimits, rlimit{Resource: unix.RLIMIT_CPU, Cur: l.CPUSeconds, Max: l.CPUSeconds})
	}
	if l.MaxFiles > 0 {
		b.rlimits = append(b.rlimits, rlimit{Resource: unix.RLIMIT_NOFILE, Cur: l.MaxFiles, Max: l.MaxFiles})
	}
	if l.MaxProcs > 0 {
		b.rlimits = append(b.rlimits, rlimit{Resource: unix.RLIMIT_NPROC, Cur: l.MaxProcs, Max: l.MaxProcs})
	}
	if l.MemoryBytes > 0 || l.CPUSeconds > 0 {
		b.watch = &watchdog{memory: l.MemoryBytes, cpu: time.Duration(l.CPUSeconds) * time.Second, interval: watchInterval}
	}
	return b
}

// accounting is the reported mechanism: the watchdog where a memory
// bound was stated (the process bound beside it is the kernel's
// rlimit either way), rlimits where any other limit was, none
// otherwise.
func (b bounds) accounting(l Limits) Accounting {
	switch {
	case l.MemoryBytes > 0:
		return AccountingWatchdog
	case l != (Limits{}):
		return AccountingRlimits
	}
	return AccountingNone
}

// watchdog samples the run's process group — the kernel's resident
// size and CPU time of each member, summed — and kills the group at
// a bound. It counts what it enforced: the peak resident size seen,
// and the kills by each bound.
type watchdog struct {
	memory   uint64
	cpu      time.Duration
	interval time.Duration

	mu       sync.Mutex
	leader   *os.Process // the group's leader, which knows whether it was reaped
	pgid     int
	peak     uint64
	memKills uint64
	cpuKills uint64
	stop     chan struct{}
	done     chan struct{}
}

// start begins sampling the group the leader leads.
func (w *watchdog) start(leader *os.Process) {
	w.leader = leader
	w.pgid = leader.Pid
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	go w.run()
}

// halt ends the sampling and waits for the last sample.
func (w *watchdog) halt() {
	if w.stop == nil {
		return
	}
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
}

func (w *watchdog) run() {
	defer close(w.done)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.sample()
		}
	}
}

// sample reads the group once and kills it where a bound is
// exceeded. The group is addressed by the leader's pid, which names
// the group only while the leader is unreaped (a zombie holds its
// pid; a reaped leader's pid may already lead another group), so a
// sample runs only while the leader is known alive through
// os.Process, which knows whether it was waited for — the same
// two-syscall window the Linux rows' group kill leaves open. A
// member the kernel no longer reports — exited between the listing
// and the reading — is skipped; a listing that fails is a sample
// missed, never a kill.
func (w *watchdog) sample() {
	if err := w.leader.Signal(syscall.Signal(0)); err != nil {
		return
	}
	members, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", w.pgid)
	if err != nil {
		return
	}
	var rss uint64
	var cpu time.Duration
	for _, m := range members {
		ti, err := taskInfo(int(m.Proc.P_pid))
		if err != nil {
			continue
		}
		rss += ti.resident
		cpu += ti.user + ti.system
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if rss > w.peak {
		w.peak = rss
	}
	switch {
	case w.memory > 0 && rss > w.memory:
		w.memKills++
	case w.cpu > 0 && cpu > w.cpu:
		w.cpuKills++
	default:
		return
	}
	_ = syscall.Kill(-w.pgid, syscall.SIGKILL)
}

// stats is the watchdog's account so far.
func (w *watchdog) stats() (peak, memKills, cpuKills uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peak, w.memKills, w.cpuKills
}

// taskReadings are the kernel's per-process readings the watchdog
// sums: the resident size and the CPU time, user and system.
type taskReadings struct {
	resident     uint64
	user, system time.Duration
}

// taskInfo reads a process through the kernel's proc_info interface
// (the libproc call proc_pidinfo wraps: call 2, flavor
// PROC_PIDTASKINFO), which an unprivileged process may read for its
// own user's processes. The task info struct opens with the virtual
// and resident sizes and the total user and system times, each eight
// bytes, in that order; the times are in the kernel's timebase
// ticks (hw.tbfrequency of them a second: twenty-four million on
// Apple silicon, a thousand million on Intel), converted here.
func taskInfo(pid int) (taskReadings, error) {
	const (
		callPidInfo      = 2
		flavorTaskInfo   = 4
		taskInfoSize     = 96
		residentOffset   = 8
		userTimeOffset   = 16
		systemTimeOffset = 24
	)
	var buf [taskInfoSize]byte
	n, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, callPidInfo, uintptr(pid), flavorTaskInfo, 0, uintptr(unsafe.Pointer(&buf[0])), taskInfoSize)
	if errno != 0 {
		return taskReadings{}, errno
	}
	if n != taskInfoSize {
		return taskReadings{}, fmt.Errorf("proc_info: %d bytes, want %d", n, taskInfoSize)
	}
	freq, err := timebase()
	if err != nil {
		return taskReadings{}, err
	}
	at := func(off int) uint64 { return *(*uint64)(unsafe.Pointer(&buf[off])) }
	ticks := func(off int) time.Duration {
		return time.Duration(float64(at(off)) * float64(time.Second) / float64(freq))
	}
	return taskReadings{
		resident: at(residentOffset),
		user:     ticks(userTimeOffset),
		system:   ticks(systemTimeOffset),
	}, nil
}

// timebase is the kernel's timebase frequency in ticks a second, read
// once.
var timebase = sync.OnceValues(func() (uint64, error) {
	if f, err := unix.SysctlUint64("hw.tbfrequency"); err == nil && f > 0 {
		return f, nil
	}
	f, err := unix.SysctlUint32("hw.tbfrequency")
	if err != nil {
		return 0, fmt.Errorf("hw.tbfrequency: %w", err)
	}
	if f == 0 {
		return 0, fmt.Errorf("hw.tbfrequency: zero")
	}
	return uint64(f), nil
})
