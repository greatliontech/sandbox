package sandbox

import "sync"

// outcome memoizes a run's reaping: the first Wait reaps and every
// later one returns what it found, a Wait that arrives while the
// first is still reaping waiting for it rather than answering with
// nothing; Destroy reads whether the reaping has ended to know
// whether a kill still has anything to end.
type outcome struct {
	mu        sync.Mutex
	releaseMu sync.Mutex
	done      chan struct{}
	finished  bool
	status    ExitStatus
	err       error
}

// begin claims the reaping: true for the first caller, who must end
// it; false for every later one, who waits for it (result).
func (o *outcome) begin() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done != nil {
		return false
	}
	o.done = make(chan struct{})
	return true
}

// end records what the reaping found and releases the waiters.
func (o *outcome) end(status ExitStatus, err error) {
	o.mu.Lock()
	o.status, o.err, o.finished = status, err, true
	o.mu.Unlock()
	close(o.done)
}

// result waits for the reaping, where one has begun, and reports it.
func (o *outcome) result() (ExitStatus, error) {
	o.mu.Lock()
	done := o.done
	o.mu.Unlock()
	if done != nil {
		<-done
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.status, o.err
}

// ended reports whether the reaping has ended: a kill after it has
// nothing to end.
func (o *outcome) ended() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.finished
}

// release runs the row's release of what the run held — the reaper's
// own, and every later Wait's retry of what failed — one at a time:
// the release must leave what it released marked so, and keep what
// failed for the next.
func (o *outcome) release(f func() error) error {
	o.releaseMu.Lock()
	defer o.releaseMu.Unlock()
	return f()
}
