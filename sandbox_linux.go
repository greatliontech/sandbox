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

	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"

	"github.com/greatliontech/sandbox/internal/nslinux"
)

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
	// Landlock is the OS row's allowlist over the world at its host
	// paths, its rights those of ABI LandlockABI; DenyNetwork is that
	// row's network denial.
	Landlock    []nslinux.LandlockRule `json:"landlock,omitempty"`
	LandlockABI int                    `json:"landlock_abi,omitempty"`
	DenyNetwork bool                   `json:"deny_network,omitempty"`
	Cmd         string                 `json:"cmd"`
	Args        []string               `json:"args,omitempty"`
	Env         []string               `json:"env"`
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

// selection is the one selection site: the host's facts and the row
// they reach for a spec granting the network or not, with what fails
// for the rows passed over. Start runs from it; reach reports it.
func selection(ctx context.Context, network bool) (hostFacts, row, []string, error) {
	facts, err := hostFactsFor(ctx)
	if err != nil {
		return hostFacts{}, row{}, nil, err
	}
	r, below := selectRow(facts, network)
	return facts, r, below, nil
}

// reach is the selection reported: Reach's answer on Linux.
func reach(ctx context.Context, spec Spec) (Isolation, []string, error) {
	_, r, below, err := selection(ctx, spec.Network)
	if err != nil {
		return None, nil, err
	}
	return r.tier, below, nil
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
	facts, r, below, err := selection(ctx, s.spec.Network)
	if err != nil {
		return err
	}
	if r.tier < s.spec.MinTier {
		return &TierError{Reached: r.tier, Required: s.spec.MinTier, Lacking: below}
	}
	w, err := resolveWorld(s.spec, r, facts.landlockABI)
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
		Landlock:    w.landlock,
		LandlockABI: facts.landlockABI,
		DenyNetwork: r.tier == OS && !s.spec.Network,
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
	if encodeErr != nil && !initUnread(encodeErr, status) {
		// The init never received a whole config; whatever it reported
		// is the consequence of this fault, not of the intent. A write
		// refused for want of a reader with nothing reported is the
		// init dead before reading, which the empty status pipe
		// reports as the death it is (startFailure).
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
	return fail(startFailure(r.tier, outcome, reason, status, ctx.Err(), waitErr))
}

// world is the resolved shape of a run: the tree to pivot to (the
// Strong row only), the binds to place there, the OS row's allowlist
// over the same world at its host paths, and the entrypoint and
// working directory as the init sees them.
type world struct {
	root     string
	binds    []bind
	landlock []nslinux.LandlockRule
	cmd      string
	workDir  string
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
// The OS row has no mount namespace, so it cannot present the tree
// at "/" (docs/specs/sandbox.md, "Root is world-restriction"): the
// world is the same tree, grants and rendezvous directory at their
// host paths, allowlisted for what each may do — the tree readable
// and executable, a read-only grant the same, a read-write grant
// and the rendezvous directory writable too — and nothing else; the
// entrypoint and the working directory are their host paths inside
// the tree, and the entrypoint must load without the image-absolute
// layout: an ELF the kernel loads whole, native, with no interpreter
// (checkELF). Without a Root the allowlist is the caller's
// whole world, the row having refused a read-only grant there.
//
// The row's own refusals come first (row.refuses). A failure is
// ErrUndeliverable: the host cannot do what was asked. landlockABI
// is the ABI the OS row's rights are spelled for.
func resolveWorld(spec Spec, r row, landlockABI int) (world, error) {
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
	// The native-ABI rule is the Strong and OS rows': their guard
	// kills a foreign-ABI call, so a foreign entrypoint could not run
	// there; under a Root the OS row loads static entrypoints only.
	checkEntry := func(string) error { return nil }
	switch r.tier {
	case Strong:
		checkEntry = func(p string) error { return checkELF(p, false) }
	case OS:
		checkEntry = func(p string) error { return checkELF(p, spec.Root != "") }
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
		if r.tier == OS {
			// The tree at its host path: the entrypoint inside it, and
			// the working directory too — the tree's root where none is
			// stated, as the pivoted row's "/" is, never the caller's.
			w.cmd = filepath.Join(root, resolved)
			w.workDir = root
		}
		if spec.WorkDir != "" {
			fi, _, err := statInTree(root, spec.WorkDir)
			if err != nil {
				return undeliverable("workdir %s is not in the tree: %v", spec.WorkDir, err)
			}
			if !fi.IsDir() {
				return undeliverable("workdir %s is not a directory in the tree", spec.WorkDir)
			}
			if r.tier == OS {
				w.workDir = filepath.Join(root, spec.WorkDir)
			}
		}
	}
	// A grant whose host path lies within the tree, or holds it — the
	// host's root over the tree's included — would make the tree
	// writable through the grant, which "never written" forbids;
	// judged on the host paths before anything else is asked of them.
	if root != "" {
		type stated struct{ path, what string }
		var paths []stated
		for _, g := range spec.PathGrants {
			paths = append(paths, stated{g.Path, "grant"})
		}
		if spec.RuntimeDir != "" {
			paths = append(paths, stated{spec.RuntimeDir, "runtime dir"})
		}
		for _, p := range paths {
			if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path {
				continue // resolveGrant refuses it by name
			}
			host, err := filepath.EvalSymlinks(p.path)
			if err != nil {
				continue // resolveGrant refuses it by name
			}
			switch {
			case host == root:
				return undeliverable("%s %s is the tree %s", p.what, p.path, spec.Root)
			case within(host, root):
				return undeliverable("%s %s lies within the tree %s", p.what, p.path, spec.Root)
			case within(root, host):
				return undeliverable("%s %s holds the tree %s", p.what, p.path, spec.Root)
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
	// subtree — meet.
	for i, a := range binds {
		for _, b := range binds[i+1:] {
			if a.Target == b.Target || strings.HasPrefix(a.Target, b.Target+"/") || strings.HasPrefix(b.Target, a.Target+"/") {
				return undeliverable("grants %s and %s overlap", a.Source, b.Source)
			}
		}
	}
	// A row without a mount namespace binds nothing: its read-write
	// grants and rendezvous directory are the host paths they already
	// are. The OS row allowlists them there instead.
	switch r.tier {
	case Strong:
		w.binds = binds
	case OS:
		w.landlock = landlockRules(root, binds, landlockABI)
	}
	return w, nil
}

// landlockRules is the OS row's allowlist over the resolved world:
// the tree, where there is one, readable and executable throughout;
// each grant at its host path, readable and executable, and with
// every right the ABI handles unless read-only; the rendezvous
// directory with every right. Without a tree, the world is the
// caller's whole, "/" with every right.
func landlockRules(root string, binds []bind, abi int) []nslinux.LandlockRule {
	readExec := nslinux.LandlockRead() | nslinux.LandlockExecute()
	everything := nslinux.LandlockFS(abi)
	var rules []nslinux.LandlockRule
	if root == "" {
		rules = append(rules, nslinux.LandlockRule{Path: "/", Access: everything})
	} else {
		rules = append(rules, nslinux.LandlockRule{Path: root, Access: readExec})
	}
	for _, b := range binds {
		access := readExec
		if !b.ReadOnly {
			access = everything
		}
		rules = append(rules, nslinux.LandlockRule{Path: b.Source, Access: access})
	}
	return rules
}

// within reports whether the canonical path p lies strictly beneath
// the canonical directory dir — every path but "/" lies beneath "/".
func within(p, dir string) bool {
	if dir == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, dir+"/")
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

// checkELF refuses an entrypoint built for a foreign machine: the
// Strong and OS rows run the native syscall ABI only, and their
// guard kills a foreign-ABI call at the first system call, so such a
// payload could not run at all — a stated intent the row cannot
// deliver, known before exec. It refuses only on a machine it
// actually read: a file that is not an ELF image (a script) or one
// that cannot be read (execute-only, or unreadable in a shared tree —
// execve needs no read permission) passes, and the arch guard is the
// backstop for what the check could not see. With static set — the
// OS row under a Root — the entrypoint must load without the
// image-absolute layout that row does not present: a file that is
// not an ELF image (a script names an interpreter the host would
// resolve), one that cannot be read, or one asking an interpreter (a
// dynamic executable, whose loader and libraries live at
// image-absolute paths) is refused, the check being the only thing
// between the payload and a wrong world.
func checkELF(path string, static bool) error {
	f, err := elf.Open(path)
	if err != nil {
		if static {
			return fmt.Errorf("cannot be read as an ELF image (%v); this row loads static ELF entrypoints from the tree only", err)
		}
		return nil
	}
	defer f.Close()
	if static {
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				return errors.New("dynamically linked: this row loads static entrypoints from the tree only, having no image-absolute layout to load against")
			}
		}
	}
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

// composeInit reads the config and composes the row's world,
// returning the config the exec needs. The Strong row sets the
// hostname, composes the world, and hardens; the Minimal row enters
// the working directory and applies the bounds, nothing else.
func composeInit() (execPlan, error) {
	fdStr := os.Getenv(envInitFD)
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return execPlan{}, fmt.Errorf("bad %s=%q: %w", envInitFD, fdStr, err)
	}
	f := os.NewFile(uintptr(fd), "sandbox-config")
	if f == nil {
		return execPlan{}, fmt.Errorf("invalid config fd %d", fd)
	}
	var cfg initConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		f.Close()
		return execPlan{}, fmt.Errorf("decode config: %w", err)
	}
	f.Close()

	// The cgroup's pids.max is opened while the host view is still
	// here and written last (see initConfig.PidsMaxFile).
	var pidsMax *os.File
	if cfg.PidsMaxFile != "" {
		pidsMax, err = os.OpenFile(cfg.PidsMaxFile, os.O_WRONLY, 0)
		if err != nil {
			return execPlan{}, fmt.Errorf("process bound: %w", err)
		}
	}
	var strong, osRow bool
	switch cfg.Row {
	case Strong.String():
		strong = true
	case OS.String():
		osRow = true
	case Minimal.String():
	default:
		// The parent names the row it selected; a name this init
		// does not know is a protocol fault, never a row to run.
		return execPlan{}, fmt.Errorf("unknown row %q", cfg.Row)
	}
	if strong {
		if cfg.Hostname != "" {
			if err := syscall.Sethostname([]byte(cfg.Hostname)); err != nil {
				return execPlan{}, fmt.Errorf("sethostname: %w", err)
			}
		}
		if err := composeWorld(cfg); err != nil {
			return execPlan{}, err
		}
	}
	if cfg.WorkDir != "" {
		if err := syscall.Chdir(cfg.WorkDir); err != nil {
			return execPlan{}, intentError{fmt.Errorf("chdir %s: %w", cfg.WorkDir, err)}
		}
	}
	if err := nslinux.SetRlimits(cfg.Rlimits); err != nil {
		return execPlan{}, intentError{err}
	}
	if osRow {
		// The OS row's allowlist over the world, which sets
		// no_new_privs, ahead of the filters.
		if err := nslinux.RestrictLandlock(cfg.LandlockABI, cfg.Landlock, cfg.DenyNetwork); err != nil {
			// A rule's path gone since the parent resolved it is the
			// intent with nowhere to land, not the mechanism failing.
			if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
				return execPlan{}, intentError{err}
			}
			return execPlan{}, err
		}
		if err := harden(func(native *arch.Info) seccomp.Policy { return osSeccompPolicy(native, !cfg.DenyNetwork) }); err != nil {
			return execPlan{}, err
		}
	}
	if strong {
		// Hardening, last and in this order (docs/specs/sandbox.md,
		// Strong row): every capability set emptied so the payload
		// holds none even as the namespace's mapped root — after the
		// mounts, which needed CAP_SYS_ADMIN — then the filters.
		if err := nslinux.DropAllCapabilities(); err != nil {
			return execPlan{}, err
		}
		if err := harden(strongSeccompPolicy); err != nil {
			return execPlan{}, err
		}
	}
	// The process-count bound, last: from here to exec nothing forks
	// or spawns a thread.
	if pidsMax != nil {
		if _, err := fmt.Fprintf(pidsMax, "%d", cfg.PidsMax); err != nil {
			return execPlan{}, fmt.Errorf("process bound: %w", err)
		}
		pidsMax.Close()
	}
	if err := nslinux.SetRlimits(cfg.LateRlimits); err != nil {
		return execPlan{}, intentError{err}
	}
	if cfg.Env == nil {
		cfg.Env = []string{}
	}
	return execPlan{Cmd: cfg.Cmd, Args: cfg.Args, Env: cfg.Env}, nil
}

// harden loads the arch guard and then the native-ABI filter policy
// gives, which deny from the moment they load and set no_new_privs.
// Each verb pins the goroutine to its thread, and exec follows on it.
func harden(policy func(*arch.Info) seccomp.Policy) error {
	native, err := arch.GetInfo("")
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	if err := nslinux.LoadArchGuard(native); err != nil {
		return err
	}
	return nslinux.LoadSeccomp(policy(native))
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

// runStage is the second stage of a staged plan, which no Linux row
// uses: an init reaching it is the protocol breached.
func runStage() {
	fmt.Fprintln(os.Stderr, "sandbox-init: no second stage on this platform")
	os.Exit(127)
}
