//go:build darwin

package sandbox

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/greatliontech/sandbox/internal/rlimit"
	"golang.org/x/sys/unix"
)

// bounds are the run's limits as this platform delivers them (docs/
// specs/sandbox.md, "Bounded means bounded"): the kernel's rlimits
// where it enforces them — CPU time, which it delivers as SIGXCPU at
// the limit, and open files — and the watchdog where it has no
// native bound an unprivileged process can set: the kernel refuses
// every memory rlimit (RLIMIT_AS, RLIMIT_DATA, RLIMIT_RSS answer
// EINVAL) and keeps its per-task memory limit for root, a payload
// that handles SIGXCPU outlives the CPU limit, and its process
// rlimit counts every process of the user rather than the run's, so
// memory, CPU time and the thread count are bounded by sampling
// the kernel's own per-process readings over the run's process group
// and killing the group at a bound.
type bounds struct {
	rlimits []rlimit.Limit
	watch   *watchdog
}

// selectBounds maps the limits to the platform's accounting.
func selectBounds(l Limits) bounds {
	var b bounds
	if l.CPUSeconds > 0 {
		b.rlimits = append(b.rlimits, rlimit.Limit{Resource: unix.RLIMIT_CPU, Cur: l.CPUSeconds, Max: l.CPUSeconds})
	}
	if l.MaxFiles > 0 {
		b.rlimits = append(b.rlimits, rlimit.Limit{Resource: unix.RLIMIT_NOFILE, Cur: l.MaxFiles, Max: l.MaxFiles})
	}
	if l.MemoryBytes > 0 || l.CPUSeconds > 0 || l.MaxProcs > 0 {
		b.watch = &watchdog{
			memory:   l.MemoryBytes,
			cpu:      time.Duration(l.CPUSeconds) * time.Second,
			procs:    l.MaxProcs,
			interval: WatchdogInterval,
		}
	}
	return b
}

// accounting is the reported mechanism: the watchdog where it bounds
// anything (memory, CPU time, the process count), rlimits where the
// open-files limit alone was stated, none otherwise.
func (b bounds) accounting() Accounting {
	switch {
	case b.watch != nil:
		return AccountingWatchdog
	case len(b.rlimits) > 0:
		return AccountingRlimits
	}
	return AccountingNone
}

// watchdog samples the run's process group — the kernel's physical
// footprint, CPU time and thread count of each member — and kills
// the group at a bound: the memory bound over the members'
// footprints summed (the platform's own measure of what a process
// costs, anonymous and compressed pages included, file-backed pages
// not: what its memory-pressure limiter reads), the CPU bound over
// each member's own time (the per-process reading RLIMIT_CPU has on
// every row), the process bound over the threads of the group's
// processes summed (every process has at least one). It counts what
// it enforced: the peak footprint seen and the one kill a bound
// made, by which bound; a failure to read the group is a bound it
// could not hold, which kills the run and is reported from Wait.
type watchdog struct {
	memory   uint64
	cpu      time.Duration
	procs    uint64
	interval time.Duration

	mu     sync.Mutex
	group  group
	peak   uint64
	kills  kills
	killed bool
	err    error
	stop   chan struct{}
	done   chan struct{}
}

// kills counts the watchdog's kills by the bound that made each:
// one at most, the group being killed once.
type kills struct {
	memory, cpu, procs uint64
}

// start begins sampling the group.
func (w *watchdog) start(g group) {
	w.group = g
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
			if !w.sample() {
				return
			}
		}
	}
}

// sample reads the group once and kills it where a bound is
// exceeded, reporting whether there is a group left to sample. A
// member the kernel no longer reports — exited between the listing
// and the reading — is skipped.
func (w *watchdog) sample() bool {
	members, err := w.group.members()
	if err != nil {
		w.fail(fmt.Errorf("sandbox: the watchdog could not list the run: %w", err))
		return false
	}
	if len(members) == 0 {
		return false
	}
	var footprint, threads uint64
	var cpuOver bool
	for _, m := range members {
		pid := int(m.Proc.P_pid)
		ru, err := rusage(pid)
		if err == nil {
			var ti taskReadings
			if ti, err = taskInfo(pid); err == nil {
				ru.threads = ti.threads
			}
		}
		if errors.Is(err, unix.ESRCH) {
			continue // exited between the listing and the reading
		}
		if err != nil {
			// A member the kernel will not show this process — one
			// that gained privilege, a setuid exec (EPERM) — or a
			// reading the kernel refuses is a bound the watchdog
			// cannot hold: a member it cannot read is not a member
			// known to be in bounds.
			w.fail(fmt.Errorf("sandbox: the watchdog could not read process %d of the run: %w", pid, err))
			return false
		}
		footprint += ru.footprint
		threads += ru.threads
		if w.cpu > 0 && ru.user+ru.system > w.cpu {
			cpuOver = true
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if footprint > w.peak {
		w.peak = footprint
	}
	var by *uint64
	switch {
	case w.memory > 0 && footprint > w.memory:
		by = &w.kills.memory
	case cpuOver:
		by = &w.kills.cpu
	case w.procs > 0 && threads > w.procs:
		by = &w.kills.procs
	default:
		return true
	}
	if !w.killed {
		*by++
	}
	w.killed = true
	_ = w.group.kill()
	return true
}

// fail records a bound the watchdog could not hold and ends the run:
// a run whose accounting cannot be read is not a run known to have
// stayed in bounds.
func (w *watchdog) fail(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.err = err
	w.killed = true
	_ = w.group.kill()
}

// stats is the watchdog's account so far: the peak footprint, its
// kills by bound, and the bound it could not hold.
func (w *watchdog) stats() (peak uint64, by kills, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peak, w.kills, w.err
}

// taskReadings are the kernel's per-process readings the watchdog
// reads: the resident size and physical footprint, the CPU time
// (user and system) and the thread count.
type taskReadings struct {
	resident     uint64
	footprint    uint64
	user, system time.Duration
	threads      uint64
}

// taskInfo reads a process through the kernel's proc_info interface
// (the libproc call proc_pidinfo wraps: call 2, flavor
// PROC_PIDTASKINFO), which an unprivileged process may read for its
// own user's processes. The task info struct opens with the virtual
// and resident sizes and the total user and system times, each eight
// bytes, in that order — the times in the kernel's timebase ticks —
// and carries the thread count as a four-byte integer at byte 84.
// The watchdog reads it for the thread count; the rest is read in
// full as the oracle the resource-usage reading is checked against.
func taskInfo(pid int) (taskReadings, error) {
	const (
		callPidInfo      = 2
		flavorTaskInfo   = 4
		taskInfoSize     = 96
		residentOffset   = 8
		userTimeOffset   = 16
		systemTimeOffset = 24
		threadsOffset    = 84
	)
	var buf [taskInfoSize]byte
	n, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, callPidInfo, uintptr(pid), flavorTaskInfo, 0, uintptr(unsafe.Pointer(&buf[0])), taskInfoSize)
	if errno != 0 {
		return taskReadings{}, errno
	}
	if n != taskInfoSize {
		return taskReadings{}, fmt.Errorf("proc_info: %d bytes, want %d", n, taskInfoSize)
	}
	r := procReading(buf[:])
	user, err := r.ticks(userTimeOffset)
	if err != nil {
		return taskReadings{}, err
	}
	system, err := r.ticks(systemTimeOffset)
	if err != nil {
		return taskReadings{}, err
	}
	return taskReadings{
		resident: r.at(residentOffset),
		user:     user,
		system:   system,
		threads:  uint64(*(*int32)(unsafe.Pointer(&buf[threadsOffset]))),
	}, nil
}

// rusage reads a process's resource usage through the kernel's
// proc_info interface (the libproc call proc_pid_rusage wraps: call
// 9, flavor RUSAGE_INFO_V0, which the kernel answers with no byte
// count): a sixteen-byte uuid, then the user and system times, the
// package idle and interrupt wakeups, the pageins, the wired and
// resident sizes and the physical footprint, each eight bytes in
// that order — the times in the kernel's timebase ticks — then the
// process's start and exit times.
func rusage(pid int) (taskReadings, error) {
	const (
		callPidRusage    = 9
		flavorV0         = 0
		rusageSize       = 96
		userTimeOffset   = 16
		systemTimeOffset = 24
		residentOffset   = 64
		footprintOffset  = 72
	)
	var buf [rusageSize]byte
	if _, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, callPidRusage, uintptr(pid), flavorV0, 0, uintptr(unsafe.Pointer(&buf[0])), 0); errno != 0 {
		return taskReadings{}, errno
	}
	r := procReading(buf[:])
	user, err := r.ticks(userTimeOffset)
	if err != nil {
		return taskReadings{}, err
	}
	system, err := r.ticks(systemTimeOffset)
	if err != nil {
		return taskReadings{}, err
	}
	return taskReadings{
		resident:  r.at(residentOffset),
		footprint: r.at(footprintOffset),
		user:      user,
		system:    system,
	}, nil
}

// procReading decodes a proc_info buffer: eight-byte fields at their
// offsets, times in the kernel's timebase ticks.
type procReading []byte

func (r procReading) at(off int) uint64 { return *(*uint64)(unsafe.Pointer(&r[off])) }

func (r procReading) ticks(off int) (time.Duration, error) {
	freq, err := timebase()
	if err != nil {
		return 0, err
	}
	return time.Duration(float64(r.at(off)) * float64(time.Second) / float64(freq)), nil
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
