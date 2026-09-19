//go:build linux

package nslinux

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"
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

const unsyncHelperEnv = "NSLINUX_UNSYNC_HELPER"

// TestInstallRefusesUnsyncableThread pins the TSYNC contract: a thread
// already under a filter of its own cannot be synchronized, seccomp(2)
// reports it by returning its id with errno clear, and the install
// must read that as failure — otherwise the process would run with
// no filter anywhere while the verb reported success. A helper
// process pins a goroutine to a thread, installs a private allow-all
// filter there without TSYNC, and then asks for a TSYNC install from
// another thread.
func TestInstallRefusesUnsyncableThread(t *testing.T) {
	if os.Getenv(unsyncHelperEnv) == "1" {
		unsyncHelper()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestInstallRefusesUnsyncableThread$", "-test.v")
	cmd.Env = append(os.Environ(), unsyncHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
}

func unsyncHelper() {
	ready := make(chan struct{})
	go func() {
		runtime.LockOSThread() // never unlocked: the thread holds its filter for the process's life
		allowAll := []unix.SockFilter{{Code: 0x06, K: unix.SECCOMP_RET_ALLOW}}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			fmt.Fprintln(os.Stderr, "sibling no_new_privs:", err)
			os.Exit(2)
		}
		fprog := unix.SockFprog{Len: 1, Filter: &allowAll[0]}
		if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
			fmt.Fprintln(os.Stderr, "sibling install:", errno)
			os.Exit(2)
		}
		close(ready)
		select {} // hold the thread, filter and all
	}()
	<-ready
	native, err := arch.GetInfo("")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	err = LoadArchGuard(native)
	if err == nil || !strings.Contains(err.Error(), "could not be synchronized") {
		fmt.Fprintf(os.Stderr, "TSYNC install beside an unsyncable thread returned %v, want a synchronization failure\n", err)
		os.Exit(3)
	}
	os.Exit(0)
}

// The kill-process action probe answers on every kernel this package
// supports (4.14 and later): filters with the action exist here.
func TestKillProcessAvailable(t *testing.T) {
	if err := KillProcessAvailable(); err != nil {
		t.Fatalf("on a kernel with seccomp filters: %v", err)
	}
}
