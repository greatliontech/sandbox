//go:build linux || darwin

// Package rlimit applies POSIX resource limits to the calling process
// on the way to an exec: the bounds a sandbox's init applies to
// itself for the payload to inherit.
package rlimit

import (
	"fmt"
	"syscall"
)

// Limit is one POSIX resource limit to apply. The JSON tags pin the
// wire keys for callers that serialize limits across a re-exec, so a
// field rename cannot silently change their protocol.
type Limit struct {
	Resource int    `json:"resource"` // unix.RLIMIT_*
	Cur      uint64 `json:"cur"`
	Max      uint64 `json:"max"`
}

// Set applies each limit to the calling process, failing on the first
// that cannot be applied. Raising a hard limit requires privilege;
// lowering never does. The applications go through syscall.Setrlimit,
// not x/sys: the Go runtime remembers the original RLIMIT_NOFILE and
// re-applies it immediately before every exec unless the stdlib's own
// Setrlimit clears that tracking — an applied bound must survive the
// exec it precedes. That clearing is process-wide, which is the other
// reason this verb belongs on the immediate pre-exec path: a
// long-lived caller applying a NOFILE limit here also changes what its
// later os/exec children inherit.
func Set(limits []Limit) error {
	for _, rl := range limits {
		if err := syscall.Setrlimit(rl.Resource, &syscall.Rlimit{Cur: rl.Cur, Max: rl.Max}); err != nil {
			return fmt.Errorf("setrlimit resource %d to %d/%d: %w", rl.Resource, rl.Cur, rl.Max, err)
		}
	}
	return nil
}
