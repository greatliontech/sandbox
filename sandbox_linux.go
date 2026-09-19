//go:build linux

package sandbox

import (
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/sys/unix"

	"github.com/greatliontech/sandbox/internal/nslinux"
)

// Internal re-exec protocol.
//
// Start re-execs /proc/self/exe with envInit set; the init() below
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

// initConfig is the JSON payload handed to the re-exec'd init process.
// Root and every bind's Target are canonical paths resolved by the
// parent: the one place the grant-to-target mapping is computed, so
// validation, the bind, and the mountinfo listing (which records
// canonical mount points) agree on one string.
type initConfig struct {
	Row      string           `json:"row"`
	Hostname string           `json:"hostname,omitempty"`
	Root     string           `json:"root,omitempty"`
	WorkDir  string           `json:"workdir,omitempty"`
	Binds    []bind           `json:"binds,omitempty"`
	Rlimits  []nslinux.Rlimit `json:"rlimits,omitempty"`
	// LateRlimits and PidsMax land right before exec: the process-count
	// bound that fits the payload does not fit the multithreaded init.
	LateRlimits []nslinux.Rlimit `json:"late_rlimits,omitempty"`
	PidsMaxFile string           `json:"pids_max_file,omitempty"`
	PidsMax     uint64           `json:"pids_max,omitempty"`
	Cmd         string           `json:"cmd"`
	Args        []string         `json:"args,omitempty"`
	Env         []string         `json:"env"`
}

// bind is one path exposed into the world: the host source, the
// canonical target it lands on (inside the tree under a Root, the
// canonical host path otherwise), and whether it is read-only.
type bind struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

type linuxSandbox struct {
	spec   Spec
	row    row // the row that ran; meaningful once cmd is set
	cmd    *exec.Cmd
	bounds bounds
	final  *Stats // the accounting read at Wait, before the cgroup went

	waited  bool // Wait's outcome is memoized: Destroy waits too
	status  ExitStatus
	waitErr error
}

func newSandbox(spec Spec) (Sandbox, error) {
	if spec.Exec == "" {
		return nil, errors.New("sandbox: Spec.Exec is required")
	}
	return &linuxSandbox{spec: spec}, nil
}

// Tier is the tier of the row that ran: the row is set only when
// Start has succeeded, so until then the zero row's tier, None, says
// nothing has applied, and from then on all-or-nothing application
// makes the selected row's tier the tier of what fully applied
// (docs/specs/sandbox.md, "Tier is derived").
func (s *linuxSandbox) Tier() Isolation { return s.row.tier }

// Start selects the row this host's facts satisfy, refuses below
// MinTier before anything is cloned, resolves the world and the
// bounds, and runs the init; it returns once the init has execed the
// target, or with why it did not.
func (s *linuxSandbox) Start(ctx context.Context) error {
	if s.cmd != nil {
		return errors.New("sandbox: already started")
	}
	facts, err := hostFactsFor(ctx)
	if err != nil {
		return err
	}
	r, below := selectRow(facts, s.spec.Network)
	if r.tier < s.spec.MinTier {
		return &TierError{Reached: r.tier, Required: s.spec.MinTier, Lacking: below}
	}
	w, err := resolveWorld(s.spec, r)
	if err != nil {
		return err
	}
	b, err := selectBounds(ctx, s.spec.Limits, nslinux.DefaultHierarchy())
	if err != nil {
		return err
	}
	// From here every failure path releases the cgroup, which nothing
	// else would, and leaves no accounting behind for a run that never
	// happened.
	fail := func(err error) error {
		if b.cgroup != nil {
			_ = b.cgroup.Delete()
		}
		s.bounds = bounds{}
		return err
	}

	env := s.spec.Env
	if env == nil {
		if s.spec.Root != "" {
			// A restricted world carries nothing of the host unstated.
			env = []string{}
		} else {
			env = hostEnv()
		}
	}
	cfg := initConfig{
		Row:         r.tier.String(),
		Hostname:    s.spec.Hostname,
		Root:        w.root,
		WorkDir:     w.workDir,
		Binds:       w.binds,
		Rlimits:     b.rlimits,
		LateRlimits: b.late,
		PidsMax:     b.pidsMax,
		Cmd:         w.cmd,
		Args:        s.spec.Args,
		Env:         env,
	}
	if b.cgroup != nil && b.pidsMax > 0 {
		cfg.PidsMaxFile = filepath.Join(b.cgroup.Dir, "pids.max")
	}

	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return fail(fmt.Errorf("sandbox: config pipe: %w", err))
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		cfgR.Close()
		cfgW.Close()
		return fail(fmt.Errorf("sandbox: status pipe: %w", err))
	}

	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	// Cancellation kills by the strongest tie the run holds (killRun).
	cmd.Cancel = func() error { return killRun(r, b, cmd.Process) }
	cmd.Stdin = s.spec.Stdin
	cmd.Stdout = s.spec.Stdout
	cmd.Stderr = s.spec.Stderr
	cmd.ExtraFiles = []*os.File{cfgR, statusW} // fds 3 and 4 in the child
	cmd.Env = append(os.Environ(),
		envInit+"=1",
		envInitFD+"=3",
		envStatusFD+"=4",
	)
	cmd.SysProcAttr = sysProcAttr(r, s.spec.Network)
	// Born bounded: the child is cloned straight into its cgroup, so
	// no instruction of it runs unaccounted and nothing migrates
	// later (rootless placement could not migrate across the
	// delegation boundary anyway).
	var cgroupFD *os.File
	if b.cgroup != nil {
		cgroupFD, err = b.cgroup.OpenFD()
		if err != nil {
			cfgR.Close()
			cfgW.Close()
			statusR.Close()
			statusW.Close()
			return fail(err)
		}
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = int(cgroupFD.Fd())
	}

	startErr := cmd.Start()
	if cgroupFD != nil {
		runtime.KeepAlive(cgroupFD)
		cgroupFD.Close()
	}
	if startErr != nil {
		cfgR.Close()
		cfgW.Close()
		statusR.Close()
		statusW.Close()
		return fail(fmt.Errorf("sandbox: start: %w", startErr))
	}
	s.bounds = b
	// The child holds its own copies; close ours so EOF can reach us.
	cfgR.Close()
	statusW.Close()

	// The config write cannot block on a child that died: the pipe
	// buffer holds it whole, and a dead reader turns the write into
	// EPIPE, which the status read below explains.
	encodeErr := json.NewEncoder(cfgW).Encode(&cfg)
	cfgW.Close()

	status, readErr := io.ReadAll(statusR)
	statusR.Close()
	if readErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fail(fmt.Errorf("sandbox: read init status: %w", readErr))
	}
	if encodeErr != nil {
		// The init never received a whole config; whatever it reported
		// is the consequence of this fault, not of the intent.
		_ = cmd.Process.Kill()
		waitErr := cmd.Wait()
		return fail(fmt.Errorf("sandbox: write init config: %v (init: %v)", encodeErr, waitErr))
	}
	outcome, reason := classifyStatus(status)
	if outcome == initExeced {
		s.cmd = cmd
		s.row = r
		return nil
	}
	// Every other shape means the init has exited: reap it so Start's
	// failure is the whole story.
	waitErr := cmd.Wait()
	return fail(startFailure(r, outcome, reason, status, ctx.Err(), waitErr))
}

// startFailure is Start's report of an init that did not reach exec,
// by the status pipe's shape: an intent the host would not deliver
// is ErrUndeliverable; a row whose mechanism failed to apply is
// reported as that, under neither refusal sentinel — the row is
// never re-selected; nothing written is a death before composing —
// a consumer package init exiting under the re-exec marker, a kill,
// or the caller's context ending — and the payload never ran.
func startFailure(r row, outcome initOutcome, reason string, status []byte, ctxErr, waitErr error) error {
	switch outcome {
	case initRefused:
		return fmt.Errorf("%w: %s", ErrUndeliverable, reason)
	case initApplyFailed:
		return fmt.Errorf("sandbox: the %s row failed to apply on this host: %s", r.tier, reason)
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

// world is the resolved shape of a run: the tree to pivot to (the
// Strong row only), the binds to place there, and the entrypoint and
// working directory as the init sees them.
type world struct {
	root    string
	binds   []bind
	cmd     string
	workDir string
}

// resolveWorld checks, before anything is cloned, that every stated
// intent has somewhere to land on row r, and resolves the world to
// canonical paths — the one place the grant-to-target mapping is
// computed. Under a Root: the Root is a directory, canonicalized; the
// entrypoint and the working directory resolve inside the tree as a
// file and a directory, symlinks chased exactly as the pivoted
// process will chase them (absolute targets re-rooted at the tree,
// ".." clamped at it); each grant and the rendezvous directory exist
// on the host and in the tree as the same kind of entry, reached
// through no symlink at any component — a pre-pivot bind would
// follow a symlink into the host view, and the post-pivot process
// would follow it into the tree, so the grant would land where the
// process cannot see it. Without a Root, grants need only exist on
// the host, and their targets are the canonical host paths — the
// mount table records canonical mount points, and a read-only
// remount must find its own bind there. Grants may not overlap one
// another or the rendezvous directory.
//
// The row's own refusals come first (row.refuses). A failure is
// ErrUndeliverable: the host cannot do what was asked.
func resolveWorld(spec Spec, r row) (world, error) {
	undeliverable := func(format string, a ...any) (world, error) {
		return world{}, fmt.Errorf("%w: "+format, append([]any{ErrUndeliverable}, a...)...)
	}
	if !filepath.IsAbs(spec.Exec) {
		return undeliverable("exec %q is not an absolute path", spec.Exec)
	}
	if spec.WorkDir != "" && !filepath.IsAbs(spec.WorkDir) {
		return undeliverable("workdir %q is not an absolute path", spec.WorkDir)
	}
	if len(spec.Hostname) > hostNameMax {
		return undeliverable("hostname %q is longer than %d bytes", spec.Hostname, hostNameMax)
	}
	if err := r.refuses(spec); err != nil {
		return world{}, err
	}
	// The native-ABI rule is the Strong row's: its guard kills a
	// foreign-ABI call, so a foreign entrypoint could not run there.
	checkEntry := func(string) error { return nil }
	if r.tier == Strong {
		checkEntry = checkNativeELF
	}
	w := world{cmd: spec.Exec, workDir: spec.WorkDir}
	var root string
	if spec.Root == "" {
		if err := checkEntry(spec.Exec); err != nil {
			return undeliverable("exec %s: %v", spec.Exec, err)
		}
	} else {
		var err error
		root, err = filepath.EvalSymlinks(spec.Root)
		if err != nil {
			return undeliverable("root %s: %v", spec.Root, err)
		}
		fi, err := os.Stat(root)
		if err != nil {
			return undeliverable("root %s: %v", spec.Root, err)
		}
		if !fi.IsDir() {
			return undeliverable("root %s is not a directory", spec.Root)
		}
		fi, resolved, err := statInTree(root, spec.Exec)
		if err != nil {
			return undeliverable("exec %s is not in the tree: %v", spec.Exec, err)
		}
		if fi.IsDir() {
			return undeliverable("exec %s is a directory in the tree", spec.Exec)
		}
		if err := checkEntry(filepath.Join(root, resolved)); err != nil {
			return undeliverable("exec %s: %v", spec.Exec, err)
		}
		w.root = root
		if spec.WorkDir != "" {
			fi, _, err := statInTree(root, spec.WorkDir)
			if err != nil {
				return undeliverable("workdir %s is not in the tree: %v", spec.WorkDir, err)
			}
			if !fi.IsDir() {
				return undeliverable("workdir %s is not a directory in the tree", spec.WorkDir)
			}
		}
	}
	var binds []bind
	for _, g := range spec.PathGrants {
		b, err := resolveGrant(root, g.Path, "grant")
		if err != nil {
			return world{}, err
		}
		b.ReadOnly = g.Access == ReadOnly
		binds = append(binds, b)
	}
	if spec.RuntimeDir != "" {
		b, err := resolveGrant(root, spec.RuntimeDir, "runtime dir")
		if err != nil {
			return world{}, err
		}
		binds = append(binds, b)
	}
	// Overlap is judged on the canonical targets, where two stated
	// spellings of one directory — or a symlink into another grant's
	// subtree — meet. A grant of the root itself would bind the host
	// over the tree, which no Root world can mean.
	for i, a := range binds {
		if root != "" && a.Target == root {
			return undeliverable("grant %s is the root of the world", a.Source)
		}
		for _, b := range binds[i+1:] {
			if a.Target == b.Target || strings.HasPrefix(a.Target, b.Target+"/") || strings.HasPrefix(b.Target, a.Target+"/") {
				return undeliverable("grants %s and %s overlap", a.Source, b.Source)
			}
		}
	}
	// A row without a mount namespace binds nothing: its read-write
	// grants and rendezvous directory are the host paths they already
	// are, and it has already refused every read-only grant.
	if r.tier == Strong {
		w.binds = binds
	}
	return w, nil
}

// resolveGrant validates one stated path and computes its bind.
func resolveGrant(root, p, what string) (bind, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return bind{}, fmt.Errorf("%w: %s %q is not a clean absolute path", ErrUndeliverable, what, p)
	}
	host, err := os.Stat(p)
	if err != nil {
		return bind{}, fmt.Errorf("%w: %s %s: %v", ErrUndeliverable, what, p, err)
	}
	if root == "" {
		target, err := filepath.EvalSymlinks(p)
		if err != nil {
			return bind{}, fmt.Errorf("%w: %s %s: %v", ErrUndeliverable, what, p, err)
		}
		return bind{Source: p, Target: target}, nil
	}
	// Every component of the target, walked from the tree down, must
	// be a real entry: a symlink anywhere on the way is a target the
	// bind and the pivoted process would resolve differently.
	dir := root
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		dir = filepath.Join(dir, seg)
		fi, err := os.Lstat(dir)
		if err != nil {
			return bind{}, fmt.Errorf("%w: %s %s has no target in the tree: %v", ErrUndeliverable, what, p, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return bind{}, fmt.Errorf("%w: %s %s passes through a symlink in the tree (%s)", ErrUndeliverable, what, p, strings.TrimPrefix(dir, root))
		}
		if dir == filepath.Join(root, p) && fi.IsDir() != host.IsDir() {
			return bind{}, fmt.Errorf("%w: %s %s is a %s on the host but a %s in the tree", ErrUndeliverable, what, p, kind(host.IsDir()), kind(fi.IsDir()))
		}
	}
	return bind{Source: p, Target: filepath.Join(root, p)}, nil
}

func kind(dir bool) string {
	if dir {
		return "directory"
	}
	return "file"
}

// statInTree stats a tree-absolute path the way the pivoted process
// will see it: symlinks are chased inside the tree, an absolute
// target re-rooted at the tree and ".." clamped at it, with the
// kernel's own bound on chained links. root must be canonical.
func statInTree(root, p string) (os.FileInfo, string, error) {
	const maxLinks = 40
	links := 0
	// rest holds the components still to walk; cur is the tree-absolute
	// directory resolved so far. The stated path is walked as written:
	// a lexical clean-up would apply ".." before the symlink it
	// follows, which is not what the kernel does.
	rest := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := "/"
	for len(rest) > 0 {
		seg := rest[0]
		rest = rest[1:]
		switch seg {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, seg)
		fi, err := os.Lstat(filepath.Join(root, next))
		if err != nil {
			return nil, "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if len(rest) == 0 {
				return fi, next, nil
			}
			if !fi.IsDir() {
				return nil, "", &os.PathError{Op: "stat", Path: p, Err: syscall.ENOTDIR}
			}
			cur = next
			continue
		}
		links++
		if links > maxLinks {
			return nil, "", &os.PathError{Op: "stat", Path: p, Err: syscall.ELOOP}
		}
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil {
			return nil, "", err
		}
		// The link's target is cleaned only of its spelling (trailing
		// slashes); its own ".." components are walked like any other.
		targetSegs := strings.Split(strings.Trim(target, "/"), "/")
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = append(targetSegs, rest...)
	}
	fi, err := os.Lstat(filepath.Join(root, cur))
	return fi, cur, err
}

// checkNativeELF refuses an entrypoint built for a foreign machine:
// the Strong row runs the native syscall ABI only, and its guard
// kills a foreign-ABI call at the first system call, so such a
// payload could not run at all — a stated intent this row cannot
// deliver, known before exec. It refuses only on a machine it
// actually read: a file that is not an ELF image (a script) or one
// that cannot be read (execute-only, or unreadable in a shared tree —
// execve needs no read permission) passes, and the arch guard is the
// backstop for what the check could not see.
func checkNativeELF(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	want, ok := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64, "386": elf.EM_386, "arm": elf.EM_ARM}[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("the native ABI on %s is unknown to this row", runtime.GOARCH)
	}
	if f.Machine != want {
		return fmt.Errorf("built for %s; this row runs %s only", f.Machine, want)
	}
	return nil
}

// Wait reaps the process and reports how it ended, together with the
// run's final accounting. The accounting is read while the cgroup
// still exists, then the cgroup is released; a run whose accounting
// cannot be read is not a run known to have stayed in bounds, and
// Wait fails. A cgroup that cannot be released yet — the kernel is
// still offlining it — keeps the exit status: Wait returns it along
// with the release error, the cgroup stays owned, and Destroy retries
// the release. Wait is memoized: Destroy waits too, and a second call
// returns the first's outcome.
func (s *linuxSandbox) Wait() (ExitStatus, error) {
	if s.cmd == nil {
		return ExitStatus{}, errors.New("sandbox: not started")
	}
	if s.waited {
		// A release that failed earlier is retried, not forgotten; the
		// outcome itself is what it was.
		if s.bounds.cgroup != nil {
			if err := s.release(); err != nil {
				return s.status, errors.Join(s.waitErr, err)
			}
		}
		return s.status, s.waitErr
	}
	s.waited = true
	err := s.cmd.Wait()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		s.waitErr = err
		return ExitStatus{}, errors.Join(err, s.release())
	}
	ps := s.cmd.ProcessState
	s.status = ExitStatus{Code: ps.ExitCode()}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		s.status.Signaled = true
		s.status.Signal = ws.Signal()
		s.status.Code = 128 + int(ws.Signal())
	}
	if s.bounds.cgroup != nil {
		st, serr := s.bounds.stats()
		if serr != nil {
			s.waitErr = serr
		} else {
			s.final = &st
		}
		if rerr := s.release(); rerr != nil {
			return s.status, errors.Join(s.waitErr, rerr)
		}
	}
	return s.status, s.waitErr
}

// release deletes the run's cgroup once; idempotent, and a failure
// leaves the cgroup owned for a later retry.
func (s *linuxSandbox) release() error {
	if s.bounds.cgroup == nil {
		return nil
	}
	if err := s.bounds.cgroup.Delete(); err != nil {
		return err
	}
	s.bounds.cgroup = nil
	return nil
}

func (s *linuxSandbox) Signal(sig os.Signal) error {
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("sandbox: not started")
	}
	return s.cmd.Process.Signal(sig)
}

// Destroy tears the sandbox down: kills the process if it still
// runs — through the cgroup where the run was placed in one — reaps
// it, and releases the cgroup. Safe after Wait, and Wait afterwards
// returns the run's outcome.
func (s *linuxSandbox) Destroy() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	if !s.waited {
		_ = killRun(s.row, s.bounds, s.cmd.Process)
		if _, err := s.Wait(); err != nil {
			return err
		}
		return nil
	}
	return s.release()
}

func (s *linuxSandbox) Stats() (Stats, error) {
	if s.final != nil {
		return *s.final, nil
	}
	return s.bounds.stats()
}

// cloneFlags returns the namespace creation flags. Network isolation (a new,
// empty net namespace) is the default; granting network shares the host's.
func cloneFlags(network bool) uintptr {
	flags := uintptr(syscall.CLONE_NEWUSER |
		syscall.CLONE_NEWNS |
		syscall.CLONE_NEWPID |
		syscall.CLONE_NEWUTS |
		syscall.CLONE_NEWIPC)
	if !network {
		flags |= syscall.CLONE_NEWNET
	}
	return flags
}

// --- re-exec'd init side ---

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
	cfg, err := composeInit()
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
	argv := append([]string{cfg.Cmd}, cfg.Args...)
	err = syscall.Exec(cfg.Cmd, argv, cfg.Env)
	// Only a failed exec returns; its reason follows the sentinel.
	report(statusFailed + fmt.Sprintf("exec %s: %v", cfg.Cmd, err))
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

// composeInit reads the config and composes the row's world,
// returning the config the exec needs. The Strong row sets the
// hostname, composes the world, and hardens; the Minimal row enters
// the working directory and applies the bounds, nothing else.
func composeInit() (*initConfig, error) {
	fdStr := os.Getenv(envInitFD)
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return nil, fmt.Errorf("bad %s=%q: %w", envInitFD, fdStr, err)
	}
	f := os.NewFile(uintptr(fd), "sandbox-config")
	if f == nil {
		return nil, fmt.Errorf("invalid config fd %d", fd)
	}
	var cfg initConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		f.Close()
		return nil, fmt.Errorf("decode config: %w", err)
	}
	f.Close()

	// The cgroup's pids.max is opened while the host view is still
	// here and written last (see initConfig.PidsMaxFile).
	var pidsMax *os.File
	if cfg.PidsMaxFile != "" {
		pidsMax, err = os.OpenFile(cfg.PidsMaxFile, os.O_WRONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("process bound: %w", err)
		}
	}
	var strong bool
	switch cfg.Row {
	case Strong.String():
		strong = true
	case Minimal.String():
	default:
		// The parent names the row it selected; a name this init
		// does not know is a protocol fault, never a row to run.
		return nil, fmt.Errorf("unknown row %q", cfg.Row)
	}
	if strong {
		if cfg.Hostname != "" {
			if err := syscall.Sethostname([]byte(cfg.Hostname)); err != nil {
				return nil, fmt.Errorf("sethostname: %w", err)
			}
		}
		if err := composeWorld(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.WorkDir != "" {
		if err := syscall.Chdir(cfg.WorkDir); err != nil {
			return nil, intentError{fmt.Errorf("chdir %s: %w", cfg.WorkDir, err)}
		}
	}
	if err := nslinux.SetRlimits(cfg.Rlimits); err != nil {
		return nil, intentError{err}
	}
	if strong {
		// Hardening, last and in this order (docs/specs/sandbox.md,
		// Strong row): every capability set emptied so the payload
		// holds none even as the namespace's mapped root — after the
		// mounts, which needed CAP_SYS_ADMIN — then the arch guard and
		// the native-ABI filter, which deny from the moment they load
		// and set no_new_privs. Each verb pins the goroutine to its
		// thread, and exec follows on it.
		if err := nslinux.DropAllCapabilities(); err != nil {
			return nil, err
		}
		native, err := arch.GetInfo("")
		if err != nil {
			return nil, fmt.Errorf("seccomp: %w", err)
		}
		if err := nslinux.LoadArchGuard(native); err != nil {
			return nil, err
		}
		if err := nslinux.LoadSeccomp(strongSeccompPolicy(native)); err != nil {
			return nil, err
		}
	}
	// The process-count bound, last: from here to exec nothing forks
	// or spawns a thread.
	if pidsMax != nil {
		if _, err := fmt.Fprintf(pidsMax, "%d", cfg.PidsMax); err != nil {
			return nil, fmt.Errorf("process bound: %w", err)
		}
		pidsMax.Close()
	}
	if err := nslinux.SetRlimits(cfg.LateRlimits); err != nil {
		return nil, intentError{err}
	}
	if cfg.Env == nil {
		cfg.Env = []string{}
	}
	return &cfg, nil
}

// composeWorld delivers the Strong row's world inside the fresh mount
// namespace (docs/specs/sandbox.md, "Root is world-restriction").
// Under a Root: every bind — grants and the rendezvous directory —
// lands on its canonical target in the tree and read-only grants are
// made read-only throughout, both while /proc is still the host's,
// since the recursive remount lists the subtree from mountinfo; then
// the tree is pivoted to "/" and remounted read-only, this mount
// only, so the binds keep their own access. The tree is never
// written: the pivot needs no scratch directory (nslinux.PivotRoot)
// and the binds land on entries the caller placed. Without a Root
// the world is the host's own view in a private mount namespace,
// where a read-only grant still means what it says, applied at the
// canonical host path its bind will be listed under.
func composeWorld(cfg initConfig) error {
	if err := nslinux.PrivatizeMounts(); err != nil {
		return err
	}
	if cfg.Root != "" {
		for _, b := range cfg.Binds {
			if err := nslinux.BindMount(b.Source, b.Target); err != nil {
				// A source or target gone since the parent resolved
				// it is the intent with nowhere to land, not the
				// mechanism failing.
				if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
					return intentError{err}
				}
				return err
			}
		}
	}
	for _, b := range cfg.Binds {
		if b.ReadOnly {
			if err := nslinux.RemountReadOnlyTree(b.Target, "/proc/self/mountinfo"); err != nil {
				return err
			}
		}
	}
	if cfg.Root == "" {
		return nil
	}
	if err := nslinux.PivotRoot(cfg.Root); err != nil {
		return err
	}
	return nslinux.RemountRootReadOnly()
}
