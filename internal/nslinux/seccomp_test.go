//go:build linux

package nslinux

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/sys/unix"
)

const seccompHelperEnv = "NSLINUX_SECCOMP_HELPER"

// TestLoadSeccompDeniesFilteredSyscall proves a loaded filter
// actually denies: a helper process (loading a filter is irreversible,
// so never in the test process) installs a policy denying uname and
// then calls it. Needs no namespaces or privilege — no_new_privs
// makes unprivileged installation legal, which LoadSeccomp sets.
func TestLoadSeccompDeniesFilteredSyscall(t *testing.T) {
	if os.Getenv(seccompHelperEnv) == "1" {
		seccompHelper()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestLoadSeccompDeniesFilteredSyscall$", "-test.v")
	cmd.Env = append(os.Environ(), seccompHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
}

func seccompHelper() {
	policy := seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{Action: seccomp.ActionErrno, Names: []string{"uname"}},
		},
	}
	if err := LoadSeccomp(policy); err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(2)
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		fmt.Fprintln(os.Stderr, "uname was allowed through the filter")
		os.Exit(3)
	}
	os.Exit(0)
}
