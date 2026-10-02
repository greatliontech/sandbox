//go:build linux || darwin

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/greatliontech/sandbox/internal/rlimit"
	"golang.org/x/sys/unix"
)

// Start re-execs the calling binary with envInit set; the init() below
// intercepts that, reads the init config from a pipe (envInitFD),
// composes the row's world — on Linux inside the namespaces the Go
// runtime created at clone time via SysProcAttr, no cgo and
// identical isolation to a C-driven clone; on darwin the bounds and
// the working directory, the profile applied by the platform's own
// applier in a second stage — then execs the target. A second pipe
// (envStatusFD) carries the outcome of composition back: the init
// marks it close-on-exec and writes one sentinel byte immediately
// before the payload's exec, then either the exec closes the pipe or
// its failure is written after the sentinel; a staged plan writes an
// applying marker instead, leaves the pipe open across the applier's
// exec, and the second stage of this binary under the applied
// mechanism writes the sentinel, so the applier's own death leaves
// the marker alone; a failure before exec is written before any
// sentinel, marked as an intent the host would not deliver or as the
// row's own mechanism failing to apply; and an init that dies
// earlier — a consumer package init exiting under the marker, a
// kill — leaves the pipe empty. Start reads the shapes apart, so a
// world that cannot be delivered refuses Start with the reason, a
// row that failed to apply is reported as that and never
// re-selected, and a payload that never ran is never reported as
// one that did.
const (
	envInit     = "_SANDBOX_INIT"
	envInitFD   = "_SANDBOX_INITFD"
	envStatusFD = "_SANDBOX_STATUSFD"
	envProbe    = "_SANDBOX_PROBE" // the re-exec is a host probe: exit at once

	statusExecing     = "\x00" // the init is about to exec the target
	statusFailed      = "E"    // an intent the host would not deliver; the reason follows
	statusApplyFailed = "A"    // the row's mechanism failed to apply; the reason follows
	statusApplying    = "S"    // the init handed the run to the row's applier (a staged plan)
	statusStaged      = "T"    // the second stage runs under the applied mechanism
)

func init() {
	switch os.Getenv(envInit) {
	case "1":
		runInit() // never returns
	case "2":
		runStage() // never returns
	}
}

// initCommon is what every platform's init config carries: the row
// the parent selected, the working directory to enter, the limits
// the init applies to itself for the payload to inherit, and the
// payload's command, arguments and environment.
type initCommon struct {
	Row     string         `json:"row"`
	WorkDir string         `json:"workdir,omitempty"`
	Rlimits []rlimit.Limit `json:"rlimits,omitempty"`
	Cmd     string         `json:"cmd"`
	Args    []string       `json:"args,omitempty"`
	Env     []string       `json:"env"`
}

// execPlan is what the init execs once the row's world is composed.
// A staged plan execs the row's applier, which applies the row's
// mechanism and execs this binary again as the second stage
// (runStage): the status pipe stays open across the applier's exec
// and the sentinel is the second stage's to write, so the applier's
// own death reads as the row failing to apply, never as the
// payload's exit (docs/specs/sandbox.md, Re-exec).
type execPlan struct {
	Cmd    string
	Args   []string
	Env    []string
	Staged bool
}

// runInit is the re-exec'd init: under the probe marker it exits at
// once, the host's answer being that the exec itself succeeded;
// otherwise it composes the row's world as the platform's
// composeInit has it and execs the plan — the payload, after the
// sentinel, or a staged plan's applier, after the applying marker —
// a failure reported through the status pipe for the parent to read
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
	if plan.Staged {
		// The applier inherits the pipe; the second stage writes the
		// sentinel. The applying marker tells the parent the applier
		// was reached, so its death reads as the row failing to apply.
		if status != nil {
			if _, err := status.WriteString(statusApplying); err != nil {
				fmt.Fprintln(os.Stderr, "sandbox-init: status pipe:", err)
				os.Exit(127)
			}
		}
		argv := append([]string{plan.Cmd}, plan.Args...)
		err = syscall.Exec(plan.Cmd, argv, plan.Env)
		// An argument list the platform refuses is the intent's size
		// (the payload's arguments and environment ride the
		// applier's), not the row failing.
		if errors.Is(err, syscall.E2BIG) {
			report(statusFailed + fmt.Sprintf("exec %s: %v", plan.Cmd, err))
		} else {
			report(statusApplyFailed + fmt.Sprintf("exec %s: %v", plan.Cmd, err))
		}
		os.Exit(127)
	}
	execPayload(status, plan)
}

// execPayload is the init's last act on every platform: the status
// pipe marked close-on-exec, the sentinel written and the payload
// execed, so the parent reads EOF exactly when the payload runs.
func execPayload(status *os.File, plan execPlan) {
	if status != nil {
		if _, err := unix.FcntlInt(status.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			fmt.Fprintln(os.Stderr, "sandbox-init: status pipe:", err)
			os.Exit(127)
		}
		if _, err := status.WriteString(statusExecing); err != nil {
			// Without the sentinel a running payload would read as a
			// death before exec; better not to run it.
			fmt.Fprintln(os.Stderr, "sandbox-init: status pipe:", err)
			os.Exit(127)
		}
	}
	argv := append([]string{plan.Cmd}, plan.Args...)
	err := syscall.Exec(plan.Cmd, argv, plan.Env)
	// Only a failed exec returns; its reason follows the sentinel.
	if status != nil {
		status.WriteString(statusFailed + fmt.Sprintf("exec %s: %v", plan.Cmd, err))
		status.Close()
	} else {
		fmt.Fprintln(os.Stderr, "sandbox-init: exec", plan.Cmd+":", err)
	}
	os.Exit(127)
}

// statusPipe opens the composition-status pipe, inheritable until the
// payload's exec marks it close-on-exec (execPayload).
func statusPipe() *os.File {
	fd, err := strconv.Atoi(os.Getenv(envStatusFD))
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), "sandbox-status")
}

// beforeConfigWrite is the seam tests set to hold the config write
// back, so an init that dies on its own is dead before the write.
var beforeConfigWrite func()

// initUnread reports whether a config write's failure is the init dead
// before reading it: the write refused for want of a reader, with
// nothing reported on the status pipe. Such a death is the empty
// status pipe's report (startFailure's initDied, the Re-exec
// clause's contract breach), never the write's; any other write
// failure is its own.
func initUnread(encodeErr error, status []byte) bool {
	return errors.Is(encodeErr, syscall.EPIPE) && len(status) == 0
}

// readInitConfig decodes the config the parent wrote for the init
// from the pipe the environment names, closing it: nothing of the
// parent's view is left open for the payload to find.
func readInitConfig[T any]() (T, error) {
	var cfg T
	fdStr := os.Getenv(envInitFD)
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return cfg, fmt.Errorf("bad %s=%q: %w", envInitFD, fdStr, err)
	}
	f := os.NewFile(uintptr(fd), "sandbox-config")
	if f == nil {
		return cfg, fmt.Errorf("invalid config fd %d", fd)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	return cfg, nil
}

// intentError marks an init failure that is the caller's intent
// failing on this host — a stated working directory the process
// cannot enter, a bound the host will not set — rather than the
// row's mechanism failing to apply; the parent reports the two apart
// (startFailure).
type intentError struct{ err error }

func (e intentError) Error() string { return e.err.Error() }
func (e intentError) Unwrap() error { return e.err }

// startFailure is Start's error for an init that did not exec the
// payload: an intent refused, the row failing to apply, or the init
// dying — by the caller's context, or by itself, which is the
// re-exec contract breached (docs/specs/sandbox.md, Re-exec).
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
		return fmt.Errorf("sandbox: %s", initBreach("the init died before exec", waitErr))
	case initApplierDied:
		if ctxErr != nil {
			return fmt.Errorf("sandbox: the init was ended before exec: %w", ctxErr)
		}
		return fmt.Errorf("sandbox: the %s row failed to apply on this host: its applier exited before the second stage ran (%v), or a package init of this binary acted under %s=2", tier, waitErr, envInit)
	case initStageDied:
		if ctxErr != nil {
			return fmt.Errorf("sandbox: the init was ended before exec: %w", ctxErr)
		}
		return fmt.Errorf("sandbox: the second stage died before exec (%v)", waitErr)
	}
	return fmt.Errorf("sandbox: unreadable init status %q", status)
}

// initBreach is the report of a re-exec'd init that died on its own
// — a package init of the calling binary acting under the marker,
// the Re-exec clause's contract breached (docs/specs/sandbox.md) —
// opening with what died, as the caller tells it.
func initBreach(what string, waitErr error) string {
	return fmt.Sprintf("%s (%v): a package init of this binary must not act under %s", what, waitErr, envInit)
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
	initApplierDied                    // the applying marker alone: the applier never reached the second stage
	initStageDied                      // the stage marker alone: the second stage died before composing
)

// classifyStatus reads the status pipe's content into an outcome and,
// for a failure, its reason.
func classifyStatus(status []byte) (initOutcome, string) {
	st := string(status)
	if strings.HasPrefix(st, statusApplying) {
		// The applier was reached: nothing after the marker is the
		// applier dying before the second stage ran, and the stage
		// marker alone is the second stage dying before composing.
		st = strings.TrimPrefix(st, statusApplying)
		if st == "" {
			return initApplierDied, ""
		}
		if !strings.HasPrefix(st, statusStaged) {
			return initGarbled, ""
		}
		st = strings.TrimPrefix(st, statusStaged)
		if st == "" {
			return initStageDied, ""
		}
	}
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

// initEnv is the re-exec'd init's environment: the markers it reads
// and nothing of the host's — the payload's environment is the
// config's to carry, and the init's own composition needs none.
func initEnv() []string {
	return []string{envInit + "=1", envInitFD + "=3", envStatusFD + "=4"}
}

// hostProbeEnv is a host probe's environment: the re-exec marker and the
// probe marker, under which the init exits at once.
func hostProbeEnv() []string {
	return []string{envInit + "=1", envProbe + "=1"}
}

// payloadEnv is the payload's environment: the stated one; where
// none is stated, empty under a Root — a restricted world carries
// nothing of the host unstated (docs/specs/sandbox.md, "Root is
// world-restriction") — and the host's own otherwise.
func payloadEnv(spec Spec) []string {
	switch {
	case spec.Env != nil:
		return spec.Env
	case spec.Root != "":
		return []string{}
	}
	return hostEnv()
}

// launchInit runs cmd as the init through the protocol: the config
// and status pipes made and handed over as descriptors 3 and 4, the
// init's environment the markers alone, cmd started, started called
// while the init is certainly alive — it blocks on its config until
// written — then the config written and the status read to its end.
// A failure of the protocol itself — a pipe, the start, started, the
// read, a write the init's own death does not explain — ends the
// init by kill, reaps it and is the error returned; otherwise the
// outcome the status says and the status itself are returned, the
// init running the payload where the outcome is initExeced and
// exited otherwise, the caller's to reap. The config write cannot
// block on a child that died: the pipe buffer holds it whole, and a
// dead reader turns the write into EPIPE, which the status read
// explains (initUnread).
func launchInit(cmd *exec.Cmd, cfg any, started func() error, kill func()) (initOutcome, string, []byte, error) {
	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return initDied, "", nil, fmt.Errorf("sandbox: config pipe: %w", err)
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		cfgR.Close()
		cfgW.Close()
		return initDied, "", nil, fmt.Errorf("sandbox: status pipe: %w", err)
	}
	cmd.Env = initEnv()
	cmd.ExtraFiles = []*os.File{cfgR, statusW}
	if err := cmd.Start(); err != nil {
		cfgR.Close()
		cfgW.Close()
		statusR.Close()
		statusW.Close()
		return initDied, "", nil, fmt.Errorf("sandbox: start: %w", err)
	}
	// The child holds its own copies; close ours so EOF can reach us.
	cfgR.Close()
	statusW.Close()
	ended := func(err error) (initOutcome, string, []byte, error) {
		cfgW.Close()
		statusR.Close()
		kill()
		waitErr := cmd.Wait()
		if waitErr != nil {
			err = fmt.Errorf("%w (init: %v)", err, waitErr)
		}
		return initDied, "", nil, err
	}
	if started != nil {
		if err := started(); err != nil {
			return ended(err)
		}
	}
	if beforeConfigWrite != nil {
		beforeConfigWrite()
	}
	encodeErr := json.NewEncoder(cfgW).Encode(cfg)
	cfgW.Close()
	status, readErr := io.ReadAll(statusR)
	statusR.Close()
	if readErr != nil {
		return ended(fmt.Errorf("sandbox: read init status: %w", readErr))
	}
	if encodeErr != nil && !initUnread(encodeErr, status) {
		// The init never received a whole config; whatever it reported
		// is the consequence of this fault, not of the intent. A write
		// refused for want of a reader with nothing reported is the
		// init dead before reading, which the empty status pipe
		// reports as the death it is (startFailure).
		return ended(fmt.Errorf("sandbox: write init config: %v", encodeErr))
	}
	outcome, reason := classifyStatus(status)
	return outcome, reason, status, nil
}

// startInit launches the init (launchInit) and reads its outcome:
// nil with the payload running, or the failure — the protocol's own,
// or the init's as startFailure reads it, the init reaped.
func startInit(ctx context.Context, tier Isolation, cmd *exec.Cmd, cfg any, started func() error, kill func()) error {
	outcome, reason, status, err := launchInit(cmd, cfg, started, kill)
	if err != nil {
		return err
	}
	if outcome == initExeced {
		return nil
	}
	// Every other shape means the init has exited: reap it so Start's
	// failure is the whole story.
	waitErr := cmd.Wait()
	return startFailure(tier, outcome, reason, status, ctx.Err(), waitErr)
}

// exitStatusOf reads how a reaped process ended: a signal death with
// the code 128 plus the signal, as a shell reports it.
func exitStatusOf(ps *os.ProcessState) ExitStatus {
	st := ExitStatus{Code: ps.ExitCode()}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		st.Signaled = true
		st.Signal = ws.Signal()
		st.Code = 128 + int(ws.Signal())
	}
	return st
}

// reaped reads a reaped payload's end from Wait's error: its exit
// status where the process ran and ended, by exit or by signal; the
// failure to wait otherwise.
func reaped(cmd *exec.Cmd, err error) (ExitStatus, error) {
	var exit *exec.ExitError
	if err == nil || errors.As(err, &exit) {
		return exitStatusOf(cmd.ProcessState), nil
	}
	return ExitStatus{}, err
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

// hostNameMax is the longest hostname a row presents: the Linux
// kernel's (__NEW_UTS_LEN), which darwin's rows, presenting none,
// never reach.
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
