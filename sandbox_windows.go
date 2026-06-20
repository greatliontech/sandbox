//go:build windows

package sandbox

import (
	"context"
	"errors"
	"os"
)

// errNotImplemented marks a backend whose surface compiles but whose mechanism
// is not built yet.
var errNotImplemented = errors.New("sandbox: windows backend not implemented " +
	"(planned: AppContainer profile + Job Object with KILL_ON_JOB_CLOSE, OS tier)")

// windowsSandbox is the placeholder for the planned AppContainer + Job Object
// backend:
//
//   - AppContainer profile (per-sandbox SID) for the security boundary;
//     network denied by withholding the internetClient capability, host paths
//     exposed by ACE'ing the container SID; integrity level Low.
//   - Job Object for resource limits (memory, CPU rate, active process count)
//     and lifecycle cleanup via JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
//   - Launch CREATE_SUSPENDED, assign to the Job, then resume.
//   - Transport is a named pipe ACL'd to the container SID (AppContainer blocks
//     loopback and TCP listen).
type windowsSandbox struct {
	spec Spec
}

func newSandbox(spec Spec) (Sandbox, error) {
	return &windowsSandbox{spec: spec}, nil
}

func (s *windowsSandbox) Start(ctx context.Context) error { return errNotImplemented }
func (s *windowsSandbox) Wait() (ExitStatus, error)       { return ExitStatus{}, errNotImplemented }
func (s *windowsSandbox) Signal(sig os.Signal) error      { return errNotImplemented }
func (s *windowsSandbox) Destroy() error                  { return nil }
func (s *windowsSandbox) Stats() (Stats, error)           { return Stats{}, errNotImplemented }
func (s *windowsSandbox) Tier() Isolation                 { return None }
