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

// watchdog samples the run's process group — the kernel's resident
// size, CPU time and thread count of each member — and kills the
// group at a bound: the memory bound over the members' resident
// sizes summed, the CPU bound over each member's own time (the
// per-process reading RLIMIT_CPU has on every row), the process
// bound over the threads of the group's processes summed (every
// process has at least one). It counts what
// it enforced: the peak resident size seen and the one kill a bound
// made; a failure to read the group is a bound it could not hold,
// which kills the run and is reported from Wait.
type watchdog struct {
	memory   uint64
	cpu      time.Duration
	procs    uint64
	interval time.Duration

	mu       sync.Mutex
	group    group
	peak     uint64
	memKills uint64
	killed   bool
	err      error
	stop     chan struct{}
	done     chan struct{}
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
	var rss, threads uint64
	var over bool
	for _, m := range members {
		ti, err := taskInfo(int(m.Proc.P_pid))
		if errors.Is(err, unix.EPERM) {
			// A member the kernel will not show this process — one
			// that gained privilege, a setuid exec — is a bound the
			// watchdog cannot hold.
			w.fail(fmt.Errorf("sandbox: the watchdog could not read process %d of the run: %w", m.Proc.P_pid, err))
			return false
		}
		if err != nil {
			continue
		}
		rss += ti.resident
		threads += ti.threads
		if w.cpu > 0 && ti.user+ti.system > w.cpu {
			over = true
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if rss > w.peak {
		w.peak = rss
	}
	if w.memory > 0 && rss > w.memory {
		if !w.killed {
			w.memKills++
		}
		over = true
	}
	if w.procs > 0 && threads > w.procs {
		over = true
	}
	if !over {
		return true
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

// stats is the watchdog's account so far.
func (w *watchdog) stats() (peak, memKills uint64, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peak, w.memKills, w.err
}

// taskReadings are the kernel's per-process readings the watchdog
// reads: the resident size, the CPU time (user and system) and the
// thread count.
type taskReadings struct {
	resident     uint64
	user, system time.Duration
	threads      uint64
}

// taskInfo reads a process through the kernel's proc_info interface
// (the libproc call proc_pidinfo wraps: call 2, flavor
// PROC_PIDTASKINFO), which an unprivileged process may read for its
// own user's processes. The task info struct opens with the virtual
// and resident sizes and the total user and system times, each eight
// bytes, in that order — the times in the kernel's timebase ticks
// (hw.tbfrequency of them a second: twenty-four million on Apple
// silicon, a thousand million on Intel), converted here — and
// carries the thread count as a four-byte integer at byte 84.
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
		threads:  uint64(*(*int32)(unsafe.Pointer(&buf[threadsOffset]))),
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
