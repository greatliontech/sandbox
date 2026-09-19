// Package testdemand is the suite's one rule for a live arm the host
// cannot deliver: it skips — unless the arm is demanded through the
// named environment variable, in which case a host that was meant to
// deliver it fails instead of skipping past it. Every live surface
// the suite has (user namespaces, cgroup placement) demands through
// it, so a demand cannot be misspelled into a skip in one place and
// not another.
package testdemand

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
)

// Live skips t where unavailable names why the host cannot deliver
// the arm, or fails it where the variable is set to a non-empty
// value; an empty unavailable is a host that delivers, and Live
// returns.
func Live(t testing.TB, variable, unavailable string) {
	t.Helper()
	if unavailable == "" {
		return
	}
	if os.Getenv(variable) != "" {
		t.Fatalf("%s is set and %s", variable, unavailable)
	}
	t.Skipf("%s", unavailable)
}

// Degrade is Live's counterpart for an arm that runs either way: it
// fails where the variable demands the surface unavailable names,
// and otherwise returns so the arm degrades to the weaker row.
func Degrade(t testing.TB, variable, unavailable string) {
	t.Helper()
	if unavailable == "" {
		return
	}
	if os.Getenv(variable) != "" {
		t.Fatalf("%s is set and %s", variable, unavailable)
	}
}

// Recorder is a testing.TB that records the one fatal or skip an arm
// under test issues, for the tests of the demands themselves: the
// real testing.T would fail or skip the test observing it. Logs are
// kept, errors recorded without ending the arm, and cleanups run
// when the arm ends; anything else of testing.TB an observed arm has
// no business calling, and panics naming it.
type Recorder struct {
	testing.TB
	FailureText string   // the failure's message, where the arm failed
	SkipText    string   // the skip's message, where the arm skipped
	Errors      []string // Error and Errorf messages, in order
	Logs        []string // Log and Logf messages, in order
	Ran         bool     // whether f ran to its end
	cleanups    []func()
}

func (r *Recorder) Helper()       {}
func (r *Recorder) Name() string  { return "observed" }
func (r *Recorder) Failed() bool  { return r.FailureText != "" || len(r.Errors) > 0 }
func (r *Recorder) Skipped() bool { return r.SkipText != "" }

func (r *Recorder) Fatalf(format string, args ...any) {
	r.FailureText = fmt.Sprintf(format, args...)
	runtime.Goexit()
}
func (r *Recorder) Fatal(args ...any) { r.Fatalf("%s", fmt.Sprintln(args...)) }
func (r *Recorder) FailNow()          { r.Fatalf("FailNow") }
func (r *Recorder) Skipf(format string, args ...any) {
	r.SkipText = fmt.Sprintf(format, args...)
	runtime.Goexit()
}
func (r *Recorder) Skip(args ...any) { r.Skipf("%s", fmt.Sprintln(args...)) }
func (r *Recorder) SkipNow()         { r.Skipf("SkipNow") }
func (r *Recorder) Errorf(format string, args ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}
func (r *Recorder) Error(args ...any) { r.Errors = append(r.Errors, fmt.Sprintln(args...)) }
func (r *Recorder) Fail()             { r.Errors = append(r.Errors, "Fail") }
func (r *Recorder) Logf(format string, args ...any) {
	r.Logs = append(r.Logs, fmt.Sprintf(format, args...))
}
func (r *Recorder) Log(args ...any)          { r.Logs = append(r.Logs, fmt.Sprintln(args...)) }
func (r *Recorder) Cleanup(f func())         { r.cleanups = append(r.cleanups, f) }
func (r *Recorder) TempDir() string          { panic("testdemand: an observed arm asked for a TempDir") }
func (r *Recorder) Setenv(key, value string) { panic("testdemand: an observed arm set " + key) }
func (r *Recorder) Chdir(dir string)         { panic("testdemand: an observed arm changed directory") }
func (r *Recorder) Context() context.Context { return context.Background() }
func (r *Recorder) Attr(key, value string)   { r.Logs = append(r.Logs, key+"="+value) }
func (r *Recorder) Output() io.Writer        { return io.Discard }
func (r *Recorder) ArtifactDir() string {
	panic("testdemand: an observed arm asked for an ArtifactDir")
}

// Observe runs f on a Recorder in its own goroutine, as the testing
// package runs a test, and returns what it recorded.
func Observe(f func(t testing.TB)) *Recorder {
	r := &Recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			for i := len(r.cleanups) - 1; i >= 0; i-- {
				r.cleanups[i]()
			}
		}()
		f(r)
		r.Ran = true
	}()
	<-done
	return r
}
