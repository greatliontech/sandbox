//go:build linux || darwin

package sandbox

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// TestClassifyStatus pins the status pipe's reading on every platform
// that re-execs: each shape the protocol writes, and the shapes it
// never does.
func TestClassifyStatus(t *testing.T) {
	for _, c := range []struct {
		in     string
		want   initOutcome
		reason string
	}{
		{"", initDied, ""},
		{statusExecing, initExeced, ""},
		{statusFailed + "why", initRefused, "why"},
		{statusApplyFailed + "how", initApplyFailed, "how"},
		{statusExecing + statusFailed + "exec x: y", initRefused, "exec x: y"},
		{statusApplying, initApplierDied, ""},
		{statusApplying + statusStaged, initStageDied, ""},
		{statusApplying + statusStaged + statusExecing, initExeced, ""},
		{statusApplying + statusStaged + statusExecing + statusFailed + "exec x: y", initRefused, "exec x: y"},
		{statusApplying + statusStaged + statusApplyFailed + "decode", initApplyFailed, "decode"},
		{statusApplying + "junk", initGarbled, ""},
		{"junk", initGarbled, ""},
	} {
		got, reason := classifyStatus([]byte(c.in))
		if got != c.want || reason != c.reason {
			t.Errorf("classifyStatus(%q) = %v %q, want %v %q", c.in, got, reason, c.want, c.reason)
		}
	}
}

// TestInitUnread pins the reading of a config write's failure: for
// want of a reader with nothing reported, the init's death; with
// anything reported, or for any other failure, the write's own.
func TestInitUnread(t *testing.T) {
	epipe := &os.PathError{Op: "write", Path: "|1", Err: syscall.EPIPE}
	for _, c := range []struct {
		err    error
		status string
		want   bool
	}{
		{epipe, "", true},
		{epipe, statusFailed + "why", false},
		{epipe, statusExecing, false},
		{&os.PathError{Op: "write", Path: "|1", Err: syscall.EBADF}, "", false},
		{errors.New("encode"), "", false},
	} {
		if got := initUnread(c.err, []byte(c.status)); got != c.want {
			t.Errorf("initUnread(%v, %q) = %v, want %v", c.err, c.status, got, c.want)
		}
	}
}
