//go:build linux

package nslinux

import (
	"fmt"
	"runtime"
	"syscall"

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

// NoNewPrivs sets PR_SET_NO_NEW_PRIVS on the calling thread: no
// execve from here on can grant privileges (setuid/setgid bits and
// file capabilities become inert). The bit is per-thread, so like
// DropAllCapabilities the verb locks the goroutine to its OS thread
// and never unlocks — it is meaningful only on the path to an
// immediate exec, which stamps the bit into the process image.
// Irreversible. Kernel >= 3.5. LoadSeccomp sets the same bit as part
// of filter installation (and TSYNC propagates it to every thread);
// this verb serves paths that harden without a filter.
func NoNewPrivs() error {
	runtime.LockOSThread() // no unlock: exec follows
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	return nil
}

// Rlimit is one POSIX resource limit to apply. The JSON tags pin the
// wire keys for callers that serialize limits across a re-exec, so a
// field rename cannot silently change their protocol.
type Rlimit struct {
	Resource int    `json:"resource"` // unix.RLIMIT_*
	Cur      uint64 `json:"cur"`
	Max      uint64 `json:"max"`
}

// SetRlimits applies each limit to the calling process, failing on
// the first that cannot be applied. Raising a hard limit requires
// CAP_SYS_RESOURCE; lowering never does. The applications go through
// syscall.Setrlimit, not x/sys: the Go runtime remembers the
// original RLIMIT_NOFILE and re-applies it immediately before every
// exec unless the stdlib's own Setrlimit clears that tracking — an
// applied bound must survive the exec it precedes. That clearing is
// process-wide, which is the other reason this verb belongs on the
// immediate pre-exec path: a long-lived caller applying a NOFILE
// limit here also changes what its later os/exec children inherit.
func SetRlimits(limits []Rlimit) error {
	for _, rl := range limits {
		if err := syscall.Setrlimit(rl.Resource, &syscall.Rlimit{Cur: rl.Cur, Max: rl.Max}); err != nil {
			return fmt.Errorf("setrlimit resource %d: %w", rl.Resource, err)
		}
	}
	return nil
}
