//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// permDenied reports whether err is the kernel refusing to create user
// namespaces (restricted host / nested-sandbox CI), in which case the spike
// can't run and the test skips rather than failing.
func permDenied(err error) bool {
	return errors.Is(err, syscall.EPERM) ||
		strings.Contains(err.Error(), "operation not permitted")
}

// TestNamespaceIsolation is the core spike: a pure-Go, create-only sandbox must
// run a process in fresh PID and UTS namespaces with no cgo.
//
//   - pid=1 proves the new PID namespace (the process is its own init).
//   - the hostname proves the new UTS namespace + Sethostname.
//   - uid=0 proves the user namespace mapping (mapped root inside, real uid out).
//
// Each assertion is load-bearing: drop CLONE_NEWPID and pid!=1; drop the
// Sethostname and the hostname won't match; drop CLONE_NEWUSER + mappings and
// uid!=0.
func TestNamespaceIsolation(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}

	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:     "/bin/sh",
		Args:     []string{"-c", "echo pid=$$ uid=$(id -u) host=$(cat /proc/sys/kernel/hostname)"},
		Hostname: "spikebox",
		Stdout:   &out,
		Stderr:   &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sb.Start(context.Background()); err != nil {
		if permDenied(err) {
			t.Skipf("user namespaces unavailable in this environment: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}

	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}

	got := out.String()
	if es.Code != 0 {
		t.Fatalf("exit code = %d, output: %q", es.Code, got)
	}
	if !strings.Contains(got, "pid=1") {
		t.Errorf("PID namespace not isolated: want pid=1, output: %q", got)
	}
	if !strings.Contains(got, "uid=0") {
		t.Errorf("user namespace not mapped: want uid=0, output: %q", got)
	}
	if !strings.Contains(got, "host=spikebox") {
		t.Errorf("UTS namespace not isolated: want host=spikebox, output: %q", got)
	}
	if sb.Tier() != Strong {
		t.Errorf("Tier() = %v, want strong", sb.Tier())
	}
}

// TestExitCodePropagation checks a non-zero exit is reported, not swallowed.
func TestExitCodePropagation(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	sb, err := New(Spec{Exec: "/bin/sh", Args: []string{"-c", "exit 7"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sb.Start(context.Background()); err != nil {
		if permDenied(err) {
			t.Skipf("user namespaces unavailable: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if es.Code != 7 {
		t.Errorf("exit code = %d, want 7", es.Code)
	}
}

// TestRootNotYetImplemented pins the honest failure for the unbuilt rootfs path.
func TestRootNotYetImplemented(t *testing.T) {
	sb, err := New(Spec{Exec: "/bin/true", Root: "/tmp/whatever"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sb.Start(context.Background()); err == nil {
		t.Fatal("expected error for Spec.Root, got nil")
	}
}
