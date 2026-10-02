//go:build windows

package sandbox

import (
	"fmt"
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
// through its completion port, on which message the run is killed —
// the one place a refused commit would leave a payload to die as it
// may; the process bound is the Job's active-process limit, which
// refuses the process past it and reports each refusal; the CPU
// bound is sampled from the Job's own account of the run's user and
// kernel time at the stated interval and the run killed past it, the
// Job's own time limit behind it as the kernel's backstop, which it
// enforces on an interval of seconds. The Job counts what it
// enforced: the peak committed memory, the kills by the memory and
// CPU bounds, the processes refused.
type bounds struct {
	job    windows.Handle
	port   windows.Handle
	memory uint64
	cpu    time.Duration
	procs  uint64

	mu        sync.Mutex
	memKills  uint64
	cpuKills  uint64
	refused   uint64
	killed    bool
	err       error
	stop      chan struct{}
	done      chan struct{}
	watchDone chan struct{}
}

// Job Object messages the completion port posts (winnt.h).
const (
	jobMsgEndOfJobTime       = 1
	jobMsgEndOfProcessTime   = 2
	jobMsgActiveProcessLimit = 3
	jobMsgActiveProcessZero  = 4
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

// messages reads the Job's completion port until the run is halted:
// a refused process counted, the memory limit's message answered
// with the run's kill, counted once.
func (b *bounds) messages() {
	defer close(b.done)
	for {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		err := windows.GetQueuedCompletionStatus(b.port, &msg, &key, &ov, 100)
		select {
		case <-b.stop:
			return
		default:
		}
		if err != nil {
			continue // the wait timed out
		}
		b.mu.Lock()
		switch msg {
		case jobMsgActiveProcessLimit:
			b.refused++
		case jobMsgJobMemoryLimit:
			if !b.killed {
				b.killed = true
				b.memKills++
				_ = windows.TerminateJobObject(b.job, killExitCode)
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
			if err != nil {
				b.mu.Lock()
				if b.err == nil {
					b.err = fmt.Errorf("sandbox: the watchdog could not read the job's account: %w", err)
					b.killed = true
					_ = windows.TerminateJobObject(b.job, killExitCode)
				}
				b.mu.Unlock()
				return
			}
			if time.Duration(a.TotalUserTime+a.TotalKernelTime)*100 > b.cpu {
				b.mu.Lock()
				if !b.killed {
					b.killed = true
					b.cpuKills++
					_ = windows.TerminateJobObject(b.job, killExitCode)
				}
				b.mu.Unlock()
				return
			}
		}
	}
}

// account reads the Job's basic accounting.
func (b *bounds) account() (jobBasicAccounting, error) {
	var a jobBasicAccounting
	var n uint32
	if err := windows.QueryInformationJobObject(b.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&a)), uint32(unsafe.Sizeof(a)), &n); err != nil {
		return a, err
	}
	return a, nil
}

// peak reads the peak committed memory the Job saw.
func (b *bounds) peak() (uint64, error) {
	var x windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var n uint32
	if err := windows.QueryInformationJobObject(b.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&x)), uint32(unsafe.Sizeof(x)), &n); err != nil {
		return 0, err
	}
	return uint64(x.PeakJobMemoryUsed), nil
}

// kill ends every process of the run.
func (b *bounds) kill() error {
	b.mu.Lock()
	b.killed = true
	b.mu.Unlock()
	return windows.TerminateJobObject(b.job, killExitCode)
}

// halt ends the readers and waits for them; the Job's handles stay
// open for the account until close.
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

// stats is the Job's account: the peak committed memory, the kills
// by the memory and CPU bounds, the processes refused, and the bound
// the watchdog could not hold.
func (b *bounds) stats() (Stats, error) {
	st := Stats{Accounting: b.accounting()}
	b.mu.Lock()
	st.MemoryKills, st.CPUKills, st.ForksRefused = b.memKills, b.cpuKills, b.refused
	err := b.err
	b.mu.Unlock()
	if b.job != 0 {
		if peak, perr := b.peak(); perr == nil {
			st.MemoryPeakBytes = peak
		} else if err == nil {
			err = fmt.Errorf("sandbox: the job's account: %w", perr)
		}
	}
	return st, err
}

// close releases the Job and its port: with the last handle the Job
// kills what it still holds (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
func (b *bounds) close() {
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
