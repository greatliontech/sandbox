//go:build linux

package sandbox

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"

	"github.com/greatliontech/sandbox/internal/nslinux"
	"github.com/greatliontech/sandbox/internal/rlimit"
	"golang.org/x/sys/unix"
)

// initConfig is the JSON payload handed to the re-exec'd init process.
// Root and every bind's Target are canonical paths resolved by the
// parent: the one place the grant-to-target mapping is computed, so
// validation, the bind, and the mountinfo listing (which records
// canonical mount points) agree on one string.
type initConfig struct {
	initCommon
	Hostname string `json:"hostname,omitempty"`
	Root     string `json:"root,omitempty"`
	Binds    []bind `json:"binds,omitempty"`
	// LateRlimits and PidsMax land right before exec: the process-count
	// and address-space bounds that fit the payload do not fit the
	// multithreaded init and its runtime's reservations.
	LateRlimits []rlimit.Limit `json:"late_rlimits,omitempty"`
	PidsMaxFile string         `json:"pids_max_file,omitempty"`
	PidsMax     uint64         `json:"pids_max,omitempty"`
	// Landlock is the OS row's allowlist over the world at its host
	// paths, its rights those of ABI LandlockABI; DenyNetwork is that
	// row's network denial.
	Landlock    []nslinux.LandlockRule `json:"landlock,omitempty"`
	LandlockABI int                    `json:"landlock_abi,omitempty"`
	DenyNetwork bool                   `json:"deny_network,omitempty"`
}

type linuxSandbox struct {
	spec   Spec
	row    row // the row that ran; meaningful once cmd is set
	cmd    *exec.Cmd
	bounds bounds
	final  *Stats // the accounting read at Wait, before the cgroup went
	// cpuKills is the CPU bound's kill, told at the reap from the dead
	// process's CPU time (Wait).
	cpuKills uint64

	outcome outcome // Wait's reaping memoized: Destroy waits too
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

	cfg := initConfig{
		initCommon:  initCommon{Row: r.tier.String(), WorkDir: w.workDir, Rlimits: b.rlimits, Cmd: w.cmd, Args: s.spec.Args, Env: payloadEnv(s.spec)},
		Hostname:    s.spec.Hostname,
		Root:        w.root,
		Binds:       w.binds,
		LateRlimits: b.late,
		PidsMax:     b.pidsMax,
		Landlock:    w.landlock,
		LandlockABI: facts.landlockABI,
		DenyNetwork: r.tier == OS && !s.spec.Network,
	}
	if b.cgroup != nil && b.pidsMax > 0 {
		cfg.PidsMaxFile = filepath.Join(b.cgroup.Dir, "pids.max")
	}
	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	// Cancellation kills by the strongest tie the run holds (killRun).
	cmd.Cancel = func() error { return killRun(r, b, cmd.Process) }
	cmd.Stdin = s.spec.Stdin
	cmd.Stdout = s.spec.Stdout
	cmd.Stderr = s.spec.Stderr
	cmd.SysProcAttr = sysProcAttr(r, s.spec.Network)
	// Born bounded: the child is cloned straight into its cgroup, so
	// no instruction of it runs unaccounted and nothing migrates
	// later (rootless placement could not migrate across the
	// delegation boundary anyway). The descriptor is closed once the
	// clone has it.
	var cgroupFD *os.File
	if b.cgroup != nil {
		cgroupFD, err = b.cgroup.OpenFD()
		if err != nil {
			return fail(err)
		}
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = int(cgroupFD.Fd())
	}
	started := func() error {
		if cgroupFD != nil {
			runtime.KeepAlive(cgroupFD)
			cgroupFD.Close()
		}
		return nil
	}
	err = startInit(ctx, r.tier, cmd, &cfg, started, func() { _ = cmd.Process.Kill() })
	if cgroupFD != nil {
		cgroupFD.Close() // a start that never ran started
	}
	if err != nil {
		return fail(err)
	}
	s.bounds = b
	s.cmd = cmd
	s.row = r
	return nil
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
// intent has somewhere to land on row r: the spelling checks, the
// row's own refusals, then the tree resolution every platform
// shares (resolveTree), mapped to the row's mechanism. The Strong
// row pivots to the tree and binds the grants and the rendezvous
// directory inside it. The OS row has no mount namespace, so it
// cannot present the tree at "/" (docs/specs/sandbox.md, "Root is
// world-restriction"): the world is the same tree, grants and
// rendezvous directory at their host paths, allowlisted for what
// each may do — the tree readable and executable, a read-only grant
// the same, a read-write grant and the rendezvous directory writable
// too — and nothing else; the entrypoint and the working directory
// are their host paths inside the tree, and the entrypoint must load
// without the image-absolute layout: an ELF the kernel loads whole,
// native, with no interpreter (checkELF). Without a Root the
// allowlist is the caller's whole world, the row having refused a
// read-only grant there. A failure is ErrUndeliverable: the host
// cannot do what was asked. landlockABI is the ABI the OS row's
// rights are spelled for.
func resolveWorld(spec Spec, r row, landlockABI int) (world, error) {
	if err := checkSpelling(spec); err != nil {
		return world{}, err
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
	t, err := resolveTree(spec, checkEntry)
	if err != nil {
		return world{}, err
	}
	w := world{cmd: spec.Exec, workDir: spec.WorkDir, root: t.root}
	if r.tier == OS {
		// The tree at its host path: the entrypoint inside it, and
		// the working directory too — the tree's root where none is
		// stated, as the pivoted row's "/" is, never the caller's.
		w.cmd, w.workDir = t.hostCmd, t.hostWorkDir
	}
	// A row without a mount namespace binds nothing: its read-write
	// grants and rendezvous directory are the host paths they already
	// are. The OS row allowlists them there instead.
	switch r.tier {
	case Strong:
		w.binds = t.binds
	case OS:
		w.landlock = landlockRules(t.root, t.binds, landlockABI)
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
	if !s.outcome.begin() {
		// A later Wait finds what the first did (waiting for it where
		// it is still reaping); a release that failed earlier is
		// retried, not forgotten, the outcome itself what it was.
		status, err := s.outcome.result()
		if s.bounds.cgroup != nil {
			if rerr := s.release(); rerr != nil {
				return status, errors.Join(err, rerr)
			}
		}
		return status, err
	}
	// The payload's own CPU time is read from its zombie before the
	// reap: the reap's rusage adds the time of every child the payload
	// reaped, which RLIMIT_CPU, a bound on the process alone, never
	// counts.
	own, ownErr := zombieCPUTime(s.cmd.Process.Pid)
	status, err := reaped(s.cmd, s.cmd.Wait())
	if err != nil {
		s.outcome.end(ExitStatus{}, err)
		return ExitStatus{}, errors.Join(err, s.release())
	}
	// RLIMIT_CPU ends the run with a kill at the limit, its soft and
	// hard limits one; the kill is the bound's where the dead
	// process's own CPU time reached the bound within the allowance
	// (cpuAllowance): the kernel checks the limit on its tick against
	// a group timer that can run a tick ahead of the time accounted,
	// and the zombie's time is read in two separately truncated clock
	// ticks. A shortfall past the allowance leaves a bound's kill
	// unattributed, never attributes another's; a kill by another
	// hand within the allowance of the bound is misattributed, the
	// cost of the allowance.
	if s.bounds.cpu > 0 && status.Signaled && status.Signal == syscall.SIGKILL && ownErr == nil && own >= s.bounds.cpu-cpuAllowance {
		s.cpuKills = 1
	}
	var waitErr error
	if s.bounds.cgroup != nil {
		st, serr := s.bounds.stats()
		if serr != nil {
			waitErr = serr
		} else {
			s.final = &st
		}
	}
	s.outcome.end(status, waitErr)
	if s.bounds.cgroup != nil {
		if rerr := s.release(); rerr != nil {
			return status, errors.Join(waitErr, rerr)
		}
	}
	return status, waitErr
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
	if !s.outcome.ended() {
		_ = killRun(s.row, s.bounds, s.cmd.Process)
	}
	_, err := s.Wait()
	return err
}

func (s *linuxSandbox) Stats() (Stats, error) {
	if s.final != nil {
		st := *s.final
		st.CPUKills = s.cpuKills
		return st, nil
	}
	st, err := s.bounds.stats()
	st.CPUKills = s.cpuKills
	return st, err
}

// cpuAllowance is how far the CPU time read from a zombie may fall
// short of the bound RLIMIT_CPU killed it at: the coarsest scheduler
// tick a Linux kernel checks the limit on (HZ=100, 10ms), and the
// two clock ticks (USER_HZ, 10ms each) the zombie's user and system
// times are separately truncated to.
const cpuAllowance = 30 * time.Millisecond

// zombieCPUTime waits for the process to exit without reaping it and
// reads its own user and system CPU time from its zombie — the
// process's alone, as /proc/<pid>/stat keeps it apart from its
// reaped children's — before the caller reaps it; a process that is
// no zombie under that pid (the caller's /proc belonging to another
// pid namespace) is refused.
func zombieCPUTime(pid int) (time.Duration, error) {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			if err != nil {
				return 0, err
			}
			break
		}
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The fields after the parenthesized command name: the state
	// first, the user and system times the twelfth and thirteenth.
	rest := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	if len(rest) < 13 {
		return 0, fmt.Errorf("/proc/%d/stat: %d fields after the name", pid, len(rest))
	}
	if rest[0] != "Z" {
		return 0, fmt.Errorf("/proc/%d/stat: no zombie under that pid (state %s)", pid, rest[0])
	}
	var ticks uint64
	for _, f := range rest[11:13] {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("/proc/%d/stat: %w", pid, err)
		}
		ticks += n
	}
	const userHz = 100 // USER_HZ, fixed by the ABI at a hundred on every architecture Go runs on
	return time.Duration(ticks) * time.Second / userHz, nil
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
	cfg, err := readInitConfig[initConfig]()
	if err != nil {
		return execPlan{}, err
	}

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
	if err := rlimit.Set(cfg.Rlimits); err != nil {
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
	if err := rlimit.Set(cfg.LateRlimits); err != nil {
		return execPlan{}, intentError{err}
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
