//go:build linux

package nslinux

import (
	"fmt"
	"runtime"
	"unsafe"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// LoadSeccomp compiles policy to a BPF program and installs it on
// every thread of the process (TSYNC), setting no_new_privs first —
// the kernel requires it for unprivileged filter installation.
// Irreversible for the process; syscalls the policy denies are denied
// from the moment this returns, so it must be the last verb before
// exec. Kernel preconditions: CONFIG_SECCOMP_FILTER; TSYNC since 3.17.
func LoadSeccomp(policy seccomp.Policy) error {
	insns, err := policy.Assemble()
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	raw, err := bpf.Assemble(insns)
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	if err := installFilter(prog); err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	return nil
}

// installFilter sets no_new_privs and installs one BPF program on
// every thread of the process. The installation is issued raw rather
// than through a library: seccomp(2) with TSYNC reports a thread it
// could not synchronize — one already under a filter of its own, as
// a consumer package init on a locked thread can leave — by returning
// that thread's id with errno clear, and a check of errno alone reads
// that as success with no filter installed anywhere. Any non-zero
// return is a failure here. The goroutine is pinned to its thread for
// the two calls and stays pinned, as every verb on the exec path
// does.
func installFilter(prog []unix.SockFilter) error {
	runtime.LockOSThread() // no unlock: exec follows
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	r1, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	if errno == unix.ENOSYS {
		return fmt.Errorf("install: seccomp filters are not supported by this kernel: %w", errno)
	}
	if errno != 0 {
		return fmt.Errorf("install: %w", errno)
	}
	if r1 != 0 {
		return fmt.Errorf("install: thread %d could not be synchronized (a filter of its own?); no filter was installed", r1)
	}
	return nil
}
