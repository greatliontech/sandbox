//go:build linux || darwin

package sandbox

import "testing"

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
