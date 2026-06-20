// Package sandbox launches a single process in an OS-enforced sandbox.
//
// It is deliberately create-only: it always creates a fresh isolated
// environment and execs one process into it. It never joins an existing
// sandbox (no "exec into a running container"). That restriction is what keeps
// it 100% pure Go on every platform — the single-threaded setns constraint that
// forces cgo in full container runtimes only applies to *joining* namespaces,
// never to *creating* them at clone time.
//
// The package exposes one cross-platform contract; each GOOS provides the
// strongest mechanism it can and reports the isolation tier actually achieved
// via Sandbox.Tier, so a caller is never silently handed a weaker guarantee
// than it asked for (see Spec.MinTier).
package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
)

// Isolation describes the strength of the boundary a sandbox achieved.
type Isolation int

const (
	// None: the process runs with no sandbox (bare exec).
	None Isolation = iota
	// Minimal: resource limits and lifecycle cleanup, but no security boundary.
	Minimal
	// OS: a capability/policy security boundary (AppContainer, Seatbelt).
	OS
	// Strong: a kernel- or VM-enforced boundary (Linux namespaces; a micro-VM).
	Strong
)

func (i Isolation) String() string {
	switch i {
	case None:
		return "none"
	case Minimal:
		return "minimal"
	case OS:
		return "os"
	case Strong:
		return "strong"
	default:
		return "unknown"
	}
}

// ErrUnsupported is returned when no sandbox backend exists for the platform.
var ErrUnsupported = errors.New("sandbox: unsupported platform")

// Access is the permission granted on a host path exposed to the sandbox.
type Access int

const (
	ReadOnly Access = iota
	ReadWrite
)

// PathGrant exposes a host path inside the sandbox at the given access level.
type PathGrant struct {
	Path   string
	Access Access
}

// Limits are resource caps applied to the sandboxed process. Zero means
// unlimited for that dimension. Backends map these to the closest native
// mechanism (cgroups, Job Object, rlimits) and may round or ignore caps they
// cannot enforce — Tier reflects what was actually achievable.
type Limits struct {
	MemoryBytes uint64 // address-space / committed-memory cap
	CPUSeconds  uint64 // CPU time cap
	MaxFiles    uint64 // open file descriptors
	MaxProcs    uint64 // process/thread count
}

// Spec describes a sandbox to create.
type Spec struct {
	// Exec is the absolute path of the binary to run inside the sandbox.
	Exec string
	Args []string
	Env  []string // nil inherits the host environment (minus internal vars)

	// WorkDir is the working directory for the process (inside the sandbox).
	WorkDir string

	// Root, if set, becomes the sandbox's root filesystem.
	Root string

	// Network grants the process host network access. When false (default) the
	// process is network-isolated as strongly as the platform allows.
	Network bool

	// PathGrants are host paths exposed into the sandbox.
	PathGrants []PathGrant

	// Limits caps process resources.
	Limits Limits

	// RuntimeDir is a host directory the transport socket/pipe lives in; it is
	// made reachable from inside the sandbox so the host and the process can
	// rendezvous across the boundary.
	RuntimeDir string

	// Hostname sets the sandbox UTS hostname (where the platform supports it).
	Hostname string

	// MinTier is the weakest isolation the caller will accept. Start fails with
	// ErrWeakerThanRequired if the platform cannot reach it.
	MinTier Isolation

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// ErrWeakerThanRequired is returned by Start when the achievable isolation is
// below Spec.MinTier.
var ErrWeakerThanRequired = errors.New("sandbox: platform cannot meet required isolation tier")

// ExitStatus reports how the sandboxed process terminated.
type ExitStatus struct {
	Code     int
	Signaled bool
	Signal   os.Signal
}

// Stats holds resource-usage counters. Reserved; backends populate what their
// native accounting exposes (cgroup/job/rusage).
type Stats struct{}

// Sandbox is a created-but-not-necessarily-started sandbox for one process.
type Sandbox interface {
	// Start launches the process. The context governs the process lifetime:
	// cancelling it terminates the sandbox.
	Start(ctx context.Context) error
	// Wait blocks until the process exits. A non-zero exit is reported in the
	// ExitStatus with a nil error; only failures to wait return an error.
	Wait() (ExitStatus, error)
	// Signal sends a signal to the sandboxed process.
	Signal(sig os.Signal) error
	// Destroy tears down the sandbox, killing the process if still running.
	Destroy() error
	// Stats returns current resource usage.
	Stats() (Stats, error)
	// Tier reports the isolation actually achieved.
	Tier() Isolation
}

// New creates a sandbox for the given spec using the platform backend.
func New(spec Spec) (Sandbox, error) {
	return newSandbox(spec)
}
