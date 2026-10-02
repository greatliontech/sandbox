//go:build linux || darwin

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Start re-execs the calling binary with envInit set; the init() below
// intercepts that, reads the init config from a pipe (envInitFD),
// composes the world inside the freshly created namespaces, then
// execs the target. The namespaces themselves are created by the Go
// runtime at clone time via SysProcAttr — no cgo, and identical
// isolation to a C-driven clone. A second pipe (envStatusFD) carries
// the outcome of composition back and is close-on-exec: the init
// writes one sentinel byte immediately before exec, then either the
// exec closes the pipe or its failure is written after the sentinel;
// a failure before exec is written before any sentinel, marked as an
// intent the host would not deliver or as the row's own mechanism
// failing to apply; and an init that dies earlier — a consumer
// package init exiting under the marker, a kill — leaves the pipe
// empty. Start reads the shapes apart, so a world that cannot be
// delivered refuses Start with the reason, a row that failed to
// apply is reported as that and never re-selected, and a payload
// that never ran is never reported as one that did.
const (
	envInit     = "_SANDBOX_INIT"
	envInitFD   = "_SANDBOX_INITFD"
	envStatusFD = "_SANDBOX_STATUSFD"
	envProbe    = "_SANDBOX_PROBE" // the re-exec is a host probe: exit at once

	statusExecing     = "\x00" // the init is about to exec the target
	statusFailed      = "E"    // an intent the host would not deliver; the reason follows
	statusApplyFailed = "A"    // the row's mechanism failed to apply; the reason follows
)

func init() {
	if os.Getenv(envInit) == "1" {
		runInit() // never returns
	}
}

// execPlan is what the init execs once the row's world is composed.
type execPlan struct {
	Cmd  string
	Args []string
	Env  []string
}

// runInit is the re-exec'd init: under the probe marker it exits at
// once, the host's answer being that the exec itself succeeded;
// otherwise it composes the row's world as the platform's
// composeInit has it, reports the sentinel and execs the plan, a
// failure reported through the status pipe for the parent to read
// apart (classifyStatus). The platform's composeInit returns the
// exec plan: the command, its arguments and its environment.
func runInit() {
	if os.Getenv(envProbe) == "1" {
		os.Exit(0) // a host probe: the clone succeeded, nothing else is asked
	}
	status := statusPipe()
	report := func(msg string) {
		if status != nil {
			status.WriteString(msg)
			status.Close()
		} else {
			fmt.Fprintln(os.Stderr, "sandbox-init:", msg)
		}
	}
	plan, err := composeInit()
	if err != nil {
		var intent intentError
		if errors.As(err, &intent) {
			report(statusFailed + err.Error())
		} else {
			report(statusApplyFailed + err.Error())
		}
		os.Exit(127)
	}
	if status != nil {
		if _, err := status.WriteString(statusExecing); err != nil {
			// Without the sentinel a running payload would read as a
			// death before exec; better not to run it.
			fmt.Fprintln(os.Stderr, "sandbox-init: status pipe:", err)
			os.Exit(127)
		}
	}
	argv := append([]string{plan.Cmd}, plan.Args...)
	err = syscall.Exec(plan.Cmd, argv, plan.Env)
	// Only a failed exec returns; its reason follows the sentinel.
	report(statusFailed + fmt.Sprintf("exec %s: %v", plan.Cmd, err))
	os.Exit(127)
}

// statusPipe opens the composition-status pipe and marks it
// close-on-exec, so the parent reads EOF exactly when the target has
// been execed.
func statusPipe() *os.File {
	fd, err := strconv.Atoi(os.Getenv(envStatusFD))
	if err != nil {
		return nil
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), "sandbox-status")
}

// intentError marks an init failure that is the caller's intent
// failing on this host — a stated working directory the process
// cannot enter, a bound the host will not set — rather than the
// row's mechanism failing to apply; the parent reports the two apart
// (startFailure).
type intentError struct{ err error }

func (e intentError) Error() string { return e.err.Error() }
func (e intentError) Unwrap() error { return e.err }

func startFailure(tier Isolation, outcome initOutcome, reason string, status []byte, ctxErr, waitErr error) error {
	switch outcome {
	case initRefused:
		return fmt.Errorf("%w: %s", ErrUndeliverable, reason)
	case initApplyFailed:
		return fmt.Errorf("sandbox: the %s row failed to apply on this host: %s", tier, reason)
	case initDied:
		if ctxErr != nil {
			return fmt.Errorf("sandbox: the init was ended before exec: %w", ctxErr)
		}
		return fmt.Errorf("sandbox: the init died before exec (%v): a package init of this binary must not act under %s", waitErr, envInit)
	}
	return fmt.Errorf("sandbox: unreadable init status %q", status)
}

// initOutcome is what the status pipe's content says happened in the
// init child.
type initOutcome int

const (
	initDied        initOutcome = iota // nothing written: died before composing
	initRefused                        // an intent refused before or at exec, with a reason
	initApplyFailed                    // the row's mechanism failed to apply, with a reason
	initExeced                         // the sentinel alone: the target is running
	initGarbled                        // a shape the protocol never writes
)

// classifyStatus reads the status pipe's content into an outcome and,
// for a failure, its reason.
func classifyStatus(status []byte) (initOutcome, string) {
	st := string(status)
	switch {
	case st == "":
		return initDied, ""
	case st == statusExecing:
		return initExeced, ""
	case strings.HasPrefix(st, statusFailed):
		return initRefused, strings.TrimSpace(strings.TrimPrefix(st, statusFailed))
	case strings.HasPrefix(st, statusApplyFailed):
		return initApplyFailed, strings.TrimSpace(strings.TrimPrefix(st, statusApplyFailed))
	case strings.HasPrefix(st, statusExecing+statusFailed):
		return initRefused, strings.TrimSpace(strings.TrimPrefix(st, statusExecing+statusFailed))
	}
	return initGarbled, ""
}

// hostEnv is the caller's environment without this package's re-exec
// markers, which name descriptors only the init child holds.
func hostEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "_SANDBOX_") {
			env = append(env, kv)
		}
	}
	return env
}

// hostNameMax is the kernel's hostname length (__NEW_UTS_LEN).
const hostNameMax = 64

// probeCache holds once-per-process answers to host probes, keyed
// by what was probed. A probe's outcome is a fact for the process's
// lifetime — an anomaly included: a consumer init that breaches the
// re-exec contract breaches it every time — but a probe the caller's
// context ended is not an answer and is not remembered. Callers
// racing for the first answer wait on the lock, bounded by the
// prober's own deadline. A host that changes underneath a running
// caller is not modelled.
type probeCache[T any] struct {
	mu      sync.Mutex
	results map[string]probeResult[T]
}

type probeResult[T any] struct {
	value T
	err   error
}

func (c *probeCache[T]) get(ctx context.Context, key string, probe func(context.Context) (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.results == nil {
		c.results = map[string]probeResult[T]{}
	}
	if r, ok := c.results[key]; ok {
		return r.value, r.err
	}
	v, err := probe(ctx)
	if ctx.Err() != nil {
		var zero T
		return zero, ctx.Err()
	}
	c.results[key] = probeResult[T]{value: v, err: err}
	return v, err
}
