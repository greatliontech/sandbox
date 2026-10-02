//go:build linux || darwin

package rlimit

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const rlimitHelperEnv = "SANDBOX_RLIMIT_HELPER"

// TestSetAppliesBothFields lowers a limit for real — in a
// helper process, since lowering a hard limit is irreversible — and
// reads back both the soft and hard fields.
func TestSetAppliesBothFields(t *testing.T) {
	if os.Getenv(rlimitHelperEnv) == "1" {
		rlimitHelper()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestSetAppliesBothFields$", "-test.v")
	cmd.Env = append(os.Environ(), rlimitHelperEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
}

func rlimitHelper() {
	if err := Set([]Limit{{Resource: unix.RLIMIT_NOFILE, Cur: 64, Max: 128}}); err != nil {
		fmt.Fprintln(os.Stderr, "set:", err)
		os.Exit(2)
	}
	var got unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &got); err != nil {
		fmt.Fprintln(os.Stderr, "get:", err)
		os.Exit(2)
	}
	if got.Cur != 64 || got.Max != 128 {
		fmt.Fprintf(os.Stderr, "rlimit = {%d %d}, want {64 128}\n", got.Cur, got.Max)
		os.Exit(3)
	}
	os.Exit(0)
}

const rlimitExecStageEnv = "SANDBOX_RLIMIT_EXEC_STAGE"

// TestSetSurviveExec pins that an applied NOFILE bound is
// still in force after syscall.Exec — the shape every re-exec'd init
// relies on. The Go runtime remembers the pre-raise soft limit and
// re-applies it just before exec unless Set routes through
// the stdlib call that clears the tracking; the helper keeps the
// hard limit unchanged precisely so that a wrongly-active restore
// would succeed (it only moves the soft limit) and be caught. The
// observer execed into is a shell, not this binary: a Go observer's
// own runtime re-raises the limit at startup, but `ulimit -n`
// prints the soft limit the exec actually delivered.
func TestSetSurviveExec(t *testing.T) {
	if os.Getenv(rlimitExecStageEnv) == "1" {
		rlimitExecHelper()
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestSetSurviveExec$", "-test.v")
	cmd.Env = append(os.Environ(), rlimitExecStageEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 || fields[len(fields)-1] != "64" {
		t.Fatalf("soft limit after exec: want 64 as the observer's last output (bound overridden at exec?)\n%s", out)
	}
}

func rlimitExecHelper() {
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(unix.RLIMIT_NOFILE, &orig); err != nil {
		fmt.Fprintln(os.Stderr, "get:", err)
		os.Exit(2)
	}
	if err := Set([]Limit{{Resource: unix.RLIMIT_NOFILE, Cur: 64, Max: orig.Max}}); err != nil {
		fmt.Fprintln(os.Stderr, "set:", err)
		os.Exit(2)
	}
	if err := syscall.Exec("/bin/sh", []string{"sh", "-c", "ulimit -n"}, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "exec:", err)
	}
	os.Exit(2)
}

func TestSetFailsLoudOnBadResource(t *testing.T) {
	err := Set([]Limit{{Resource: 1000, Cur: 1, Max: 1}})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("want EINVAL for unknown resource, got %v", err)
	}
}

func TestSetStopsAtFirstFailure(t *testing.T) {
	var cur unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &cur); err != nil {
		t.Fatal(err)
	}
	err := Set([]Limit{
		{Resource: 1000, Cur: 1, Max: 1},
		{Resource: unix.RLIMIT_CORE, Cur: 0, Max: 0},
	})
	if err == nil {
		t.Fatal("want error from the failing limit")
	}
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatal(err)
	}
	if after != cur {
		t.Error("limits after the failing entry must not be applied")
	}
}
