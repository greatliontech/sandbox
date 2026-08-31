//go:build linux

package nslinux

import (
	"fmt"

	seccomp "github.com/elastic/go-seccomp-bpf"
)

// LoadSeccomp compiles policy to a BPF program and installs it on
// every thread of the process (TSYNC), setting no_new_privs first —
// the kernel requires it for unprivileged filter installation.
// Irreversible for the process; syscalls the policy denies are denied
// from the moment this returns, so it must be the last verb before
// exec. Kernel preconditions: CONFIG_SECCOMP_FILTER; TSYNC since 3.17.
func LoadSeccomp(policy seccomp.Policy) error {
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy:     policy,
	}
	if err := seccomp.LoadFilter(filter); err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	return nil
}
