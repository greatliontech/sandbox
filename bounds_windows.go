//go:build windows

package sandbox

import (
	"fmt"
	"math"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// bounds are the run's limits as this platform delivers them (docs/
// specs/sandbox.md, "Bounded means bounded"): a Job Object every
// process of the run is born into, which kills them all with its last
// handle. The memory bound is the Job's own, over the run's committed
// memory summed, which the Job refuses past the bound and reports
// through its completion port — the report the bound's enforcement,
// on which the run is killed, a payload dying of the refused commit
// first or not; the process bound is the Job's active-process limit,
// which refuses the process past it and reports each refusal; the
// CPU bound is sampled from the Job's own account of the run's user
// and kernel time at the stated interval and the run killed past it,
// the Job's own time limit (user time alone) behind it as the
// kernel's backstop, which it enforces on an interval of seconds and
// reports too. The Job counts what it enforced: the peak committed
// memory, the enforcements of the memory and CPU bounds, the
// processes refused.
type bounds struct {
	memory uint64
	cpu    time.Duration
	procs  uint64

	mu        sync.Mutex // guards the handles and the counters
	job       windows.Handle
	port      windows.Handle
	memKills  uint64
	cpuKills  uint64
	refused   uint64
	killed    bool // a bound's kill made: no second
	finished  bool // the run ended by the payload's exit or a kill from outside the bounds
	err       error
	stop      chan struct{}
	done      chan struct{}
	watchDone chan struct{}
}

// Job Object messages the completion port posts (winnt.h).
const (
	jobMsgEndOfJobTime       = 1
	jobMsgActiveProcessLimit = 3
	jobMsgJobMemoryLimit     = 10

	jobObjectAssociateCompletionPort = 7
)

type jobAssociateCompletionPort struct {
	CompletionKey  uintptr
	CompletionPort windows.Handle
}

type jobBasicAccounting struct {
	TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
}

// newBounds makes the run's Job with the limits stated.
func newBounds(l Limits) (*bounds, error) {
	if l.MemoryBytes > math.MaxUint32 && unsafe.Sizeof(uintptr(0)) == 4 {
		return nil, fmt.Errorf("%w: a memory bound of %d bytes exceeds what this platform's word holds", ErrUndeliverable, l.MemoryBytes)
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("sandbox: job object: %w", err)
	}
	b := &bounds{job: job, memory: l.MemoryBytes, cpu: time.Duration(l.CPUSeconds) * time.Second, procs: l.MaxProcs}
	limits := &windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if l.MemoryBytes > 0 {
		limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		limits.JobMemoryLimit = uintptr(l.MemoryBytes)
	}
	if l.CPUSeconds > 0 {
		limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_TIME
		limits.BasicLimitInformation.PerJobUserTimeLimit = int64(l.CPUSeconds) * 10_000_000 // hundreds of nanoseconds
	}
	if l.MaxProcs > 0 {
		limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		limits.BasicLimitInformation.ActiveProcessLimit = uint32(l.MaxProcs)
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(limits)), uint32(unsafe.Sizeof(*limits))); err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("sandbox: job limits: %w", err)
	}
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		windows.CloseHandle(job)
		return nil, fmt.Errorf("sandbox: job completion port: %w", err)
	}
	assoc := jobAssociateCompletionPort{CompletionKey: 1, CompletionPort: port}
	if _, err := windows.SetInformationJobObject(job, jobObjectAssociateCompletionPort, uintptr(unsafe.Pointer(&assoc)), uint32(unsafe.Sizeof(assoc))); err != nil {
		windows.CloseHandle(port)
		windows.CloseHandle(job)
		return nil, fmt.Errorf("sandbox: job completion port: %w", err)
	}
	b.port = port
	return b, nil
}

// accounting is the reported mechanism: the Job where any bound was
// stated, none otherwise.
func (b *bounds) accounting() Accounting {
	if b.memory > 0 || b.cpu > 0 || b.procs > 0 {
		return AccountingJobObject
	}
	return AccountingNone
}

// assign places the process in the Job before it runs.
func (b *bounds) assign(process windows.Handle) error {
	if err := windows.AssignProcessToJobObject(b.job, process); err != nil {
		return fmt.Errorf("sandbox: assign to job: %w", err)
	}
	return nil
}

// start begins reading the Job's messages and, under a CPU bound,
// sampling its account.
func (b *bounds) start() {
	b.stop = make(chan struct{})
	b.done = make(chan struct{})
	go b.messages()
	if b.cpu > 0 {
		b.watchDone = make(chan struct{})
		go b.watch()
	}
}

// messages reads the Job's completion port until the run is halted,
// then what the port still holds: a refused process counted; the
// memory limit's report — the bound's enforcement, the commit refused
// — answered with the run's kill and counted, whether or not the
// payload outlives its refused commit to be killed; the Job's own
// time limit's report, the backstop's kill, counted as the CPU
// bound's.
func (b *bounds) messages() {
	defer close(b.done)
	for {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		b.mu.Lock()
		port := b.port
		b.mu.Unlock()
		if port == 0 {
			return
		}
		err := windows.GetQueuedCompletionStatus(port, &msg, &key, &ov, 100)
		stopped := false
		select {
		case <-b.stop:
			stopped = true
		default:
		}
		if err != nil {
			if stopped {
				return // the port drained
			}
			continue // the wait timed out
		}
		b.mu.Lock()
		switch msg {
		case jobMsgActiveProcessLimit:
			b.refused++
		case jobMsgJobMemoryLimit:
			// The bound's enforcement, counted whether the run was
			// ended already — the payload dead of the refused commit
			// before the report was read — or not.
			if b.memKills+b.cpuKills == 0 {
				b.memKills++
				b.end()
			}
		case jobMsgEndOfJobTime:
			if b.memKills+b.cpuKills == 0 {
				b.cpuKills++
				b.end()
			}
		}
		b.mu.Unlock()
	}
}

// watch samples the Job's account every WatchdogInterval and kills
// the run past the CPU bound.
func (b *bounds) watch() {
	defer close(b.watchDone)
	t := time.NewTicker(WatchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			a, err := b.account()
			b.mu.Lock()
			switch {
			case err != nil:
				if b.err == nil {
					b.err = fmt.Errorf("sandbox: the watchdog could not read the job's account: %w", err)
					b.end()
				}
				b.mu.Unlock()
				return
			case time.Duration(a.TotalUserTime+a.TotalKernelTime)*100 > b.cpu:
				if !b.killed && !b.finished && b.memKills+b.cpuKills == 0 {
					b.cpuKills++
					b.end()
				}
				b.mu.Unlock()
				return
			}
			b.mu.Unlock()
		}
	}
}

// end terminates the Job as a bound's kill, once; called with the
// lock held.
func (b *bounds) end() {
	b.killed = true
	if b.job != 0 {
		_ = windows.TerminateJobObject(b.job, killExitCode)
	}
}

// finish terminates the Job at the run's end — the payload's exit,
// Destroy, cancellation — which is no bound's kill: a report the
// port still holds is the bound's enforcement all the same.
func (b *bounds) finish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.finished = true
	if b.job != 0 {
		_ = windows.TerminateJobObject(b.job, killExitCode)
	}
}

// account reads the Job's basic accounting, the handle held under
// the lock through the read.
func (b *bounds) account() (jobBasicAccounting, error) {
	var a jobBasicAccounting
	var n uint32
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.job == 0 {
		return a, fmt.Errorf("the job is closed")
	}
	if err := windows.QueryInformationJobObject(b.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&a)), uint32(unsafe.Sizeof(a)), &n); err != nil {
		return a, err
	}
	return a, nil
}

// peak reads the peak committed memory the Job saw, the handle held
// under the lock through the read.
func (b *bounds) peak() (uint64, error) {
	var x windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var n uint32
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.job == 0 {
		return 0, fmt.Errorf("the job is closed")
	}
	if err := windows.QueryInformationJobObject(b.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&x)), uint32(unsafe.Sizeof(x)), &n); err != nil {
		return 0, err
	}
	return uint64(x.PeakJobMemoryUsed), nil
}

// kill ends every process of the run from outside the bounds —
// cancellation, Destroy — where the Job is still open.
func (b *bounds) kill() { b.finish() }

// halt ends the readers and waits for them, the port's remaining
// messages read on the way out; the Job's handles stay open for the
// account until close. The caller ends the run first (kill), so
// that no process is left to keep the port busy.
func (b *bounds) halt() {
	if b.stop == nil {
		return
	}
	select {
	case <-b.stop:
	default:
		close(b.stop)
	}
	<-b.done
	if b.watchDone != nil {
		<-b.watchDone
	}
}

// stats is the Job's account: the peak committed memory, the
// enforcements of the memory and CPU bounds, the processes refused,
// and the bound the watchdog could not hold.
func (b *bounds) stats() (Stats, error) {
	st := Stats{Accounting: b.accounting()}
	b.mu.Lock()
	st.MemoryKills, st.CPUKills, st.ForksRefused = b.memKills, b.cpuKills, b.refused
	err := b.err
	open := b.job != 0
	b.mu.Unlock()
	if open {
		if peak, perr := b.peak(); perr == nil {
			st.MemoryPeakBytes = peak
		} else if err == nil {
			err = fmt.Errorf("sandbox: the job's account: %w", perr)
		}
	}
	return st, err
}

// close releases the Job and its port: with the last handle the Job
// kills what it still holds (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
// nothing reads the handles after.
func (b *bounds) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.port != 0 {
		windows.CloseHandle(b.port)
		b.port = 0
	}
	if b.job != 0 {
		windows.CloseHandle(b.job)
		b.job = 0
	}
}

// killExitCode is the exit code of a process the sandbox ended: what
// a SIGKILL death reads as on the unix rows, 128 plus the signal.
const killExitCode = 137
