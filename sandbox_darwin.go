//go:build darwin

package sandbox

import (
	"context"
	"errors"
	"os"
)

// errNotImplemented marks a backend whose surface compiles but whose mechanism
// is not built yet.
var errNotImplemented = errors.New("sandbox: darwin backend not implemented " +
	"(planned: sandbox-exec SBPL profile + setrlimit, OS tier)")

// darwinSandbox is the placeholder for the planned Seatbelt backend:
//
//   - An SBPL profile (deny default; allow the rootfs/system reads, granted
//     paths, and the transport socket) applied via sandbox-exec.
//   - setrlimit for resource caps (RLIMIT_AS / CPU / NOFILE / NPROC); no
//     cgroup-equivalent, so memory control is coarse.
//   - A process group killed on context cancellation (escapable by
//     setsid). darwin has no parent-death tie, so a caller killed with
//     SIGKILL leaves the process running — weaker than Linux/Windows
//     cleanup, and stated in the contract.
//
// sandbox-exec is deprecated and undocumented; the backend must probe its
// availability at runtime and degrade Tier to Minimal (rlimit + pgroup only)
// rather than report OS when the security boundary is unavailable.
type darwinSandbox struct {
	spec Spec
}

func newSandbox(spec Spec) (Sandbox, error) {
	return &darwinSandbox{spec: spec}, nil
}

func (s *darwinSandbox) Start(ctx context.Context) error { return errNotImplemented }
func (s *darwinSandbox) Wait() (ExitStatus, error)       { return ExitStatus{}, errNotImplemented }
func (s *darwinSandbox) Signal(sig os.Signal) error      { return errNotImplemented }
func (s *darwinSandbox) Destroy() error                  { return nil }
func (s *darwinSandbox) Stats() (Stats, error)           { return Stats{}, errNotImplemented }
func (s *darwinSandbox) Tier() Isolation                 { return None }
