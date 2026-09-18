//go:build linux

package nslinux

import (
	"fmt"

	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/sys/unix"
)

// LoadArchGuard installs a seccomp filter that kills the process at
// its first system call made through any syscall ABI other than
// native's (an i386 call from a 64-bit process via int 0x80, or a
// 32-bit payload on a 64-bit kernel). A policy filter assembled for
// the native ABI lets foreign-ABI calls through untouched, so without
// this guard every denial it states is a denial of one ABI out of
// the two the kernel exposes. Filters stack and the most severe
// verdict wins, so the guard composes with any policy loaded before
// or after it. native is the architecture the policy is assembled
// for — the policy's assembler resolves the running architecture the
// same way the caller does, so the two agree by construction of the
// same lookup, not by a shared value. Installed on every
// thread (TSYNC), no_new_privs set, a partial sync refused
// (installFilter). Irreversible. Kernel preconditions:
// CONFIG_SECCOMP_FILTER; SECCOMP_RET_KILL_PROCESS since 4.14.
func LoadArchGuard(native *arch.Info) error {
	const (
		bpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
		bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
		bpfRetK   = 0x06 // BPF_RET | BPF_K
		archOff   = 4    // offsetof(struct seccomp_data, arch)
	)
	prog := []unix.SockFilter{
		{Code: bpfLdWAbs, K: archOff},
		{Code: bpfJeqK, K: uint32(native.ID), Jt: 1, Jf: 0},
		{Code: bpfRetK, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: bpfRetK, K: unix.SECCOMP_RET_ALLOW},
	}
	if err := installFilter(prog); err != nil {
		return fmt.Errorf("seccomp arch guard: %w", err)
	}
	return nil
}
