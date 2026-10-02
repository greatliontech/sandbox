//go:build linux

package nslinux

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// DropAllCapabilities empties every capability set of the calling
// thread: the bounding set (so no execve can regain a capability),
// then permitted/effective/inheritable via capset, then the ambient
// set. It locks the goroutine to its OS thread and never unlocks —
// capability state is per-thread, so the verb is meaningful only on
// the path to an immediate exec, which replaces every thread with the
// capability-free image. Kernel preconditions: CAP_SETPCAP in the
// current user namespace for the bounding drops (a fresh user
// namespace's mapped root holds it); the ambient set exists since
// kernel 4.3.
func DropAllCapabilities() error {
	runtime.LockOSThread() // no unlock: exec follows

	last, err := lastCap()
	if err != nil {
		return fmt.Errorf("drop capabilities: probe last cap: %w", err)
	}
	for v := 0; v <= last; v++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(v), 0, 0, 0); err != nil {
			return fmt.Errorf("drop capabilities: bounding drop %d: %w", v, err)
		}
	}

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("drop capabilities: capset: %w", err)
	}

	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("drop capabilities: clear ambient: %w", err)
	}
	return nil
}

// lastCap probes the kernel for the highest supported capability bit
// by reading the bounding set upward until the kernel reports EINVAL.
func lastCap() (int, error) {
	for c := 0; c < 64; c++ {
		if _, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0); err != nil {
			if c == 0 {
				return 0, err
			}
			return c - 1, nil
		}
	}
	return 63, nil
}
