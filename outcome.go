package sandbox

import "sync"

// outcome memoizes a run's reaping: the first Wait reaps and every
// later one returns what it found, a Wait that arrives while the
// first is still reaping waiting for it rather than answering with
// nothing; Destroy reads whether the reaping has ended to know
// whether a kill still has anything to end.
type outcome struct {
	mu       sync.Mutex
	done     chan struct{}
	finished bool
	status   ExitStatus
	err      error
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

// fail records a failure to wait a later caller must see, where the
// reaping ended with one.
func (o *outcome) fail(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err == nil {
		o.err = err
	}
}
