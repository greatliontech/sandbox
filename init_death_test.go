//go:build linux || darwin

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A consumer package init acting under the re-exec marker, for the
// test of its report: package-level variables initialize before any
// init function runs, this file's included, so a marker file named
// by the parent's pid makes the re-exec'd init exit before it reads
// its config — the breach the Re-exec clause names.
var _ = func() int {
	if os.Getenv(envInit) == "" {
		// The test process: a marker a killed predecessor of the same
		// pid left behind would kill every init below; none is kept.
		os.Remove(initDeathMarker(os.Getpid()))
		return 0
	}
	if os.Getenv(envInit) == "1" && os.Getenv(envProbe) == "" {
		if _, err := os.Stat(initDeathMarker(os.Getppid())); err == nil {
			os.Exit(3)
		}
	}
	return 0
}()

// initDeathMarker names the marker beside this binary: a place the
// init child, whose environment is the markers alone (no TMPDIR),
// spells exactly as the test process does.
func initDeathMarker(pid int) string {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return filepath.Join(filepath.Dir(exe), "sandbox-init-death-"+strconv.Itoa(pid))
}

// TestInitDeathReported pins the Re-exec clause's report on every
// platform that re-execs: an init that dies before reading its
// config is reported by Start as that death — never as the config
// write's failure for want of a reader — and nothing runs.
func TestInitDeathReported(t *testing.T) {
	overrideMinimal(t)
	marker := initDeathMarker(os.Getpid())
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(marker) })
	// The write held back past the init's death, so the write fails
	// for want of a reader and the death is what the report must be
	// read from.
	beforeConfigWrite = func() { time.Sleep(500 * time.Millisecond) }
	t.Cleanup(func() { beforeConfigWrite = nil })
	var out strings.Builder
	sb, err := New(Spec{Exec: "/bin/sh", Args: []string{"-c", "echo ran"}, Network: true, Limits: Limits{MaxFiles: 256}, Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}
	err = sb.Start(context.Background())
	if err == nil || errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "must not act under "+envInit) {
		t.Fatalf("Start = %v, want the init's death reported", err)
	}
	if out.Len() != 0 || sb.Tier() != None {
		t.Fatalf("something ran under a dead init: %q, tier %v", out.String(), sb.Tier())
	}
}
