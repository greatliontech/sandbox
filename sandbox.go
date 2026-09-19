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
//
// Re-exec: pure-Go namespace creation runs the calling binary itself
// as the sandbox's init — Start re-execs /proc/self/exe with an
// internal marker in the environment, and this package's init takes
// over inside the fresh namespaces. Every package init of the calling
// binary runs there first, in that child, before the takeover. A
// consumer's init must therefore be free of side effects the marker
// environment would make wrong (see docs/specs/sandbox.md, Re-exec).
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
	// None: the floor MinTier can state — accept any row. No backend
	// reports it; sandbox never bare-execs.
	None Isolation = iota
	// Minimal: kernel-enforced resource bounds with their accounting
	// reported, but no security boundary.
	Minimal
	// OS: an OS-policy security boundary (Landlock, Seatbelt,
	// AppContainer).
	OS
	// Strong: a kernel-enforced boundary (Linux namespaces).
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

// PathGrant exposes a host path inside the sandbox, at the same
// absolute path, at the given access level; a read-only grant is
// read-only throughout, submounts included. Under a stated Root the
// path must already exist in the tree as the same kind of entry
// (directory or file), reached through no symlink at any component —
// the tree is the caller's to shape, and a grant with nowhere to land
// is an undeliverable intent (ErrUndeliverable), never a silent
// omission. Grants may not overlap one another or RuntimeDir: two
// intents over one path have no single delivery.
type PathGrant struct {
	Path   string
	Access Access
}

// Limits are resource caps applied to the sandboxed process. Zero means
// unlimited for that dimension. A backend maps them to the strongest
// native accounting the selected row admits (docs/specs/sandbox.md,
// "Bounded means bounded") and reports which one enforced them
// (Stats.Accounting); it never rounds a cap silently — a cap it
// cannot enforce refuses Start.
type Limits struct {
	// MemoryBytes caps memory: memory.max of the sandbox's own cgroup
	// under cgroups — the payload is killed at the bound; RLIMIT_AS
	// under rlimits, which caps address space rather than use — a
	// runtime that reserves more address space than the cap (a Go
	// binary reserves well over 64 MiB) is refused at its very start,
	// loudly. Which of the two enforced it is reported
	// (Stats.Accounting).
	MemoryBytes uint64
	CPUSeconds  uint64 // CPU time cap (rlimits on every row)
	MaxFiles    uint64 // open file descriptors (rlimits on every row)
	// MaxProcs caps the process and thread count: pids.max of the
	// sandbox's own cgroup under cgroups; RLIMIT_NPROC under rlimits,
	// which current kernels count within the sandbox's user namespace
	// (older ones over every task of the user, the host's included, so
	// a value below that count refuses the payload its first thread).
	// Which of the two enforced it is reported (Stats.Accounting).
	MaxProcs uint64
}

// Accounting names the native mechanism that enforced a run's Limits
// — a reported fact of the run, so a bound-exceeded death is
// attributable to a specific enforcement.
type Accounting int

const (
	// AccountingNone: no limit was stated, so nothing enforced one.
	AccountingNone Accounting = iota
	// AccountingRlimits: POSIX resource limits on the process.
	AccountingRlimits
	// AccountingCgroups: a cgroup v2 the process was born into.
	AccountingCgroups
	// AccountingJobObject: a Windows Job Object.
	AccountingJobObject
)

func (a Accounting) String() string {
	switch a {
	case AccountingNone:
		return "none"
	case AccountingRlimits:
		return "rlimits"
	case AccountingCgroups:
		return "cgroups"
	case AccountingJobObject:
		return "job-object"
	default:
		return "unknown"
	}
}

// Spec describes a sandbox to create.
type Spec struct {
	// Exec is the absolute path of the binary to run inside the sandbox
	// — under a Root, a tree-absolute path resolved inside the tree.
	Exec string
	Args []string
	// Env is the process environment. nil inherits the host's (minus
	// internal variables) when no Root is stated; under a Root the
	// world is exactly the tree and the grants, and nil means an empty
	// environment — nothing of the host leaks in unstated.
	Env []string

	// WorkDir is the working directory for the process (inside the sandbox).
	WorkDir string

	// Root, if set, bounds the process's world to exactly this tree,
	// the PathGrants, and RuntimeDir — presented at "/" on rows with
	// mount namespaces, read-only except where a grant says otherwise
	// (docs/specs/sandbox.md, "Root is world-restriction"). Exec,
	// WorkDir, grant paths, and RuntimeDir are then tree-absolute, and
	// the entrypoint comes from the tree. The tree itself is never
	// written: nothing is created in it, not even transiently.
	Root string

	// Network grants the process the host's network. When false (default)
	// the process has no network: on rows with namespaces a fresh, empty
	// network namespace (a loopback, down), and on the others whatever
	// the row's mechanism set states (docs/specs/sandbox.md, the ladder).
	Network bool

	// PathGrants are host paths exposed into the sandbox.
	PathGrants []PathGrant

	// Limits caps process resources.
	Limits Limits

	// RuntimeDir is a host directory the transport socket/pipe lives in; it is
	// made reachable, read-write, from inside the sandbox at the same path so
	// the host and the process can rendezvous across the boundary. Under a
	// stated Root the path must exist in the tree as a directory, like a
	// PathGrant.
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

// ErrUndeliverable is returned by Start when a stated intent cannot be
// delivered on this host at all — a grant with no target in the tree,
// a Root that is not a directory — as distinct from
// ErrWeakerThanRequired: "this host cannot do what you asked" rather
// than "this host cannot do it strongly enough".
var ErrUndeliverable = errors.New("sandbox: intent cannot be delivered on this host")

// ExitStatus reports how the sandboxed process terminated.
type ExitStatus struct {
	Code     int
	Signaled bool
	Signal   os.Signal
}

// Stats are the run's accounting facts: which mechanism enforced the
// memory and process-count limits — the CPU-time and open-files
// limits are rlimits on every row, so a CPU-time death is always
// RLIMIT_CPU's — and, where the mechanism keeps counters (cgroups),
// the peak memory use and the bound enforcements that happened:
// processes the memory bound killed, forks the process bound
// refused. Zero counters under rlimits mean the mechanism does not
// count, not that nothing happened; a zero peak under cgroups on a
// kernel before 5.19 means the kernel keeps no peak.
type Stats struct {
	Accounting      Accounting
	MemoryPeakBytes uint64
	MemoryKills     uint64
	ForksRefused    uint64
}

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
	// Stats returns the run's accounting facts: live while the process
	// runs, final after Wait.
	Stats() (Stats, error)
	// Tier reports the isolation actually achieved.
	Tier() Isolation
}

// New creates a sandbox for the given spec using the platform backend.
func New(spec Spec) (Sandbox, error) {
	return newSandbox(spec)
}
