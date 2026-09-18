//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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
// a composition failure is written before any sentinel; and an init
// that dies earlier — a consumer package init exiting under the
// marker, a kill — leaves the pipe empty. Start reads the three
// shapes apart, so a world that cannot be delivered refuses Start
// with the reason and a payload that never ran is never reported as
// one that did.
const (
	envInit     = "_SANDBOX_INIT"
	envInitFD   = "_SANDBOX_INITFD"
	envStatusFD = "_SANDBOX_STATUSFD"

	statusExecing = "\x00" // the init is about to exec the target
	statusFailed  = "E"    // followed by the reason
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
	Hostname string           `json:"hostname,omitempty"`
	Root     string           `json:"root,omitempty"`
	WorkDir  string           `json:"workdir,omitempty"`
	Binds    []bind           `json:"binds,omitempty"`
	Rlimits  []nslinux.Rlimit `json:"rlimits,omitempty"`
	Cmd      string           `json:"cmd"`
	Args     []string         `json:"args,omitempty"`
	Env      []string         `json:"env"`
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
	cmd    *exec.Cmd
	exited bool
}

func newSandbox(spec Spec) (Sandbox, error) {
	if spec.Exec == "" {
		return nil, errors.New("sandbox: Spec.Exec is required")
	}
	// The create-only Linux backend is always kernel-enforced (Strong); refuse
	// up front if the caller demanded something we structurally cannot exceed.
	if spec.MinTier > Strong {
		return nil, ErrWeakerThanRequired
	}
	return &linuxSandbox{spec: spec}, nil
}

func (s *linuxSandbox) Tier() Isolation { return Strong }

func (s *linuxSandbox) Start(ctx context.Context) error {
	if s.cmd != nil {
		return errors.New("sandbox: already started")
	}
	root, binds, err := resolveWorld(s.spec)
	if err != nil {
		return err
	}

	env := s.spec.Env
	if env == nil {
		if s.spec.Root != "" {
			// A restricted world carries nothing of the host unstated.
			env = []string{}
		} else {
			env = os.Environ()
		}
	}
	cfg := initConfig{
		Hostname: s.spec.Hostname,
		Root:     root,
		WorkDir:  s.spec.WorkDir,
		Binds:    binds,
		Rlimits:  buildRlimits(s.spec.Limits),
		Cmd:      s.spec.Exec,
		Args:     s.spec.Args,
		Env:      env,
	}

	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("sandbox: config pipe: %w", err)
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		cfgR.Close()
		cfgW.Close()
		return fmt.Errorf("sandbox: status pipe: %w", err)
	}

	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Stdin = s.spec.Stdin
	cmd.Stdout = s.spec.Stdout
	cmd.Stderr = s.spec.Stderr
	cmd.ExtraFiles = []*os.File{cfgR, statusW} // fds 3 and 4 in the child
	cmd.Env = append(os.Environ(),
		envInit+"=1",
		envInitFD+"=3",
		envStatusFD+"=4",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  cloneFlags(s.spec.Network),
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// GidMappingsEnableSetgroups defaults false → Go writes "deny" to
		// /proc/<pid>/setgroups, required for an unprivileged gid_map.
		Pdeathsig: syscall.SIGKILL, // child dies if the host process dies
	}

	if err := cmd.Start(); err != nil {
		cfgR.Close()
		cfgW.Close()
		statusR.Close()
		statusW.Close()
		return fmt.Errorf("sandbox: start: %w", err)
	}
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
		return fmt.Errorf("sandbox: read init status: %w", readErr)
	}
	if encodeErr != nil {
		// The init never received a whole config; whatever it reported
		// is the consequence of this fault, not of the intent.
		_ = cmd.Process.Kill()
		waitErr := cmd.Wait()
		return fmt.Errorf("sandbox: write init config: %v (init: %v)", encodeErr, waitErr)
	}
	outcome, reason := classifyStatus(status)
	if outcome == initExeced {
		s.cmd = cmd
		return nil
	}
	// Every other shape means the init has exited: reap it so Start's
	// failure is the whole story.
	waitErr := cmd.Wait()
	switch outcome {
	case initRefused:
		return fmt.Errorf("%w: %s", ErrUndeliverable, reason)
	case initDied:
		// Nothing was written: the init died before composing — a
		// consumer package init exiting under the re-exec marker, a
		// kill, or the caller's context ending — and the payload
		// never ran.
		if ctx.Err() != nil {
			return fmt.Errorf("sandbox: the init was ended before exec: %w", ctx.Err())
		}
		return fmt.Errorf("sandbox: the init died before exec (%v): a package init of this binary must not act under %s", waitErr, envInit)
	}
	return fmt.Errorf("sandbox: unreadable init status %q", status)
}

// initOutcome is what the status pipe's content says happened in the
// init child.
type initOutcome int

const (
	initDied    initOutcome = iota // nothing written: died before composing
	initRefused                    // composition or exec refused, with a reason
	initExeced                     // the sentinel alone: the target is running
	initGarbled                    // a shape the protocol never writes
)

// classifyStatus reads the status pipe's content into an outcome and,
// for a refusal, its reason.
func classifyStatus(status []byte) (initOutcome, string) {
	st := string(status)
	switch {
	case st == "":
		return initDied, ""
	case st == statusExecing:
		return initExeced, ""
	case strings.HasPrefix(st, statusFailed):
		return initRefused, strings.TrimSpace(strings.TrimPrefix(st, statusFailed))
	case strings.HasPrefix(st, statusExecing+statusFailed):
		return initRefused, strings.TrimSpace(strings.TrimPrefix(st, statusExecing+statusFailed))
	}
	return initGarbled, ""
}

// resolveWorld checks, before anything is cloned, that every stated
// intent has somewhere to land, and resolves the world to canonical
// paths — the one place the grant-to-target mapping is computed.
// Under a Root: the Root is a directory, canonicalized; the
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
// another or the rendezvous directory. A failure is ErrUndeliverable:
// the host cannot do what was asked.
func resolveWorld(spec Spec) (root string, binds []bind, err error) {
	if !filepath.IsAbs(spec.Exec) {
		return "", nil, fmt.Errorf("%w: exec %q is not an absolute path", ErrUndeliverable, spec.Exec)
	}
	if spec.WorkDir != "" && !filepath.IsAbs(spec.WorkDir) {
		return "", nil, fmt.Errorf("%w: workdir %q is not an absolute path", ErrUndeliverable, spec.WorkDir)
	}
	if spec.Root != "" {
		root, err = filepath.EvalSymlinks(spec.Root)
		if err != nil {
			return "", nil, fmt.Errorf("%w: root %s: %v", ErrUndeliverable, spec.Root, err)
		}
		fi, err := os.Stat(root)
		if err != nil {
			return "", nil, fmt.Errorf("%w: root %s: %v", ErrUndeliverable, spec.Root, err)
		}
		if !fi.IsDir() {
			return "", nil, fmt.Errorf("%w: root %s is not a directory", ErrUndeliverable, spec.Root)
		}
		if fi, err := statInTree(root, spec.Exec); err != nil {
			return "", nil, fmt.Errorf("%w: exec %s is not in the tree: %v", ErrUndeliverable, spec.Exec, err)
		} else if fi.IsDir() {
			return "", nil, fmt.Errorf("%w: exec %s is a directory in the tree", ErrUndeliverable, spec.Exec)
		}
		if spec.WorkDir != "" {
			if fi, err := statInTree(root, spec.WorkDir); err != nil {
				return "", nil, fmt.Errorf("%w: workdir %s is not in the tree: %v", ErrUndeliverable, spec.WorkDir, err)
			} else if !fi.IsDir() {
				return "", nil, fmt.Errorf("%w: workdir %s is not a directory in the tree", ErrUndeliverable, spec.WorkDir)
			}
		}
	}
	for _, g := range spec.PathGrants {
		b, err := resolveGrant(root, g.Path, "grant")
		if err != nil {
			return "", nil, err
		}
		b.ReadOnly = g.Access == ReadOnly
		binds = append(binds, b)
	}
	if spec.RuntimeDir != "" {
		b, err := resolveGrant(root, spec.RuntimeDir, "runtime dir")
		if err != nil {
			return "", nil, err
		}
		binds = append(binds, b)
	}
	// Overlap is judged on the canonical targets, where two stated
	// spellings of one directory — or a symlink into another grant's
	// subtree — meet. A grant of the root itself would bind the host
	// over the tree, which no Root world can mean.
	for i, a := range binds {
		if root != "" && a.Target == root {
			return "", nil, fmt.Errorf("%w: grant %s is the root of the world", ErrUndeliverable, a.Source)
		}
		for _, b := range binds[i+1:] {
			if a.Target == b.Target || strings.HasPrefix(a.Target, b.Target+"/") || strings.HasPrefix(b.Target, a.Target+"/") {
				return "", nil, fmt.Errorf("%w: grants %s and %s overlap", ErrUndeliverable, a.Source, b.Source)
			}
		}
	}
	return root, binds, nil
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
func statInTree(root, p string) (os.FileInfo, error) {
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
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if len(rest) == 0 {
				return fi, nil
			}
			if !fi.IsDir() {
				return nil, &os.PathError{Op: "stat", Path: p, Err: syscall.ENOTDIR}
			}
			cur = next
			continue
		}
		links++
		if links > maxLinks {
			return nil, &os.PathError{Op: "stat", Path: p, Err: syscall.ELOOP}
		}
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil {
			return nil, err
		}
		// The link's target is cleaned only of its spelling (trailing
		// slashes); its own ".." components are walked like any other.
		targetSegs := strings.Split(strings.Trim(target, "/"), "/")
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = append(targetSegs, rest...)
	}
	return os.Lstat(filepath.Join(root, cur))
}

func (s *linuxSandbox) Wait() (ExitStatus, error) {
	if s.cmd == nil {
		return ExitStatus{}, errors.New("sandbox: not started")
	}
	err := s.cmd.Wait()
	s.exited = true

	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return ExitStatus{}, err
	}
	ps := s.cmd.ProcessState
	es := ExitStatus{Code: ps.ExitCode()}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		es.Signaled = true
		es.Signal = ws.Signal()
		es.Code = 128 + int(ws.Signal())
	}
	return es, nil
}

func (s *linuxSandbox) Signal(sig os.Signal) error {
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("sandbox: not started")
	}
	return s.cmd.Process.Signal(sig)
}

func (s *linuxSandbox) Destroy() error {
	if s.cmd == nil || s.cmd.Process == nil || s.exited {
		return nil
	}
	return s.cmd.Process.Kill()
}

func (s *linuxSandbox) Stats() (Stats, error) { return Stats{}, nil }

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

func buildRlimits(l Limits) []nslinux.Rlimit {
	var out []nslinux.Rlimit
	if l.MemoryBytes > 0 {
		out = append(out, nslinux.Rlimit{Resource: unix.RLIMIT_AS, Cur: l.MemoryBytes, Max: l.MemoryBytes})
	}
	if l.CPUSeconds > 0 {
		out = append(out, nslinux.Rlimit{Resource: unix.RLIMIT_CPU, Cur: l.CPUSeconds, Max: l.CPUSeconds})
	}
	if l.MaxFiles > 0 {
		out = append(out, nslinux.Rlimit{Resource: unix.RLIMIT_NOFILE, Cur: l.MaxFiles, Max: l.MaxFiles})
	}
	if l.MaxProcs > 0 {
		out = append(out, nslinux.Rlimit{Resource: unix.RLIMIT_NPROC, Cur: l.MaxProcs, Max: l.MaxProcs})
	}
	return out
}

// --- re-exec'd init side ---

func runInit() {
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
		report(statusFailed + err.Error())
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

// composeInit reads the config and composes the world, returning the
// config the exec needs.
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

	if cfg.Hostname != "" {
		if err := syscall.Sethostname([]byte(cfg.Hostname)); err != nil {
			return nil, fmt.Errorf("sethostname: %w", err)
		}
	}
	if err := composeWorld(cfg); err != nil {
		return nil, err
	}
	if cfg.WorkDir != "" {
		if err := syscall.Chdir(cfg.WorkDir); err != nil {
			return nil, fmt.Errorf("chdir %s: %w", cfg.WorkDir, err)
		}
	}
	if err := nslinux.SetRlimits(cfg.Rlimits); err != nil {
		return nil, err
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
