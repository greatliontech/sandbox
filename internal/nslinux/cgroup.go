//go:build linux

package nslinux

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Hierarchy locates the cgroup v2 unified hierarchy. The zero value
// is unusable; use DefaultHierarchy for the live kernel interface.
// Tests point the three paths at fixture trees, which is what keeps
// every cgroup verb unit-testable without namespaces or privilege.
type Hierarchy struct {
	Root           string // cgroup2 mount point
	ProcMounts     string // mount table, normally /proc/mounts
	ProcSelfCgroup string // own membership, normally /proc/self/cgroup
}

// DefaultHierarchy returns the live kernel interface paths.
func DefaultHierarchy() *Hierarchy {
	return &Hierarchy{
		Root:           "/sys/fs/cgroup",
		ProcMounts:     "/proc/mounts",
		ProcSelfCgroup: "/proc/self/cgroup",
	}
}

// root returns Root in canonical form, so path comparison and the
// ancestry walk are insensitive to how the caller spelled it.
func (h *Hierarchy) root() string {
	return filepath.Clean(h.Root)
}

// Mounted reports whether a cgroup2 filesystem is mounted at Root.
func (h *Hierarchy) Mounted() (bool, error) {
	data, err := os.ReadFile(h.ProcMounts)
	if err != nil {
		return false, fmt.Errorf("cgroup: read mounts: %w", err)
	}
	return mountsHaveCgroup2(data, h.root()), nil
}

// mountsHaveCgroup2 reports whether the mount table lists a cgroup2
// filesystem at root.
func mountsHaveCgroup2(procMounts []byte, root string) bool {
	for line := range bytes.Lines(procMounts) {
		f := strings.Fields(string(line))
		if len(f) >= 3 && f[2] == "cgroup2" && f[1] == root {
			return true
		}
	}
	return false
}

// SelfDir returns the calling process's own cgroup directory.
func (h *Hierarchy) SelfDir() (string, error) {
	data, err := os.ReadFile(h.ProcSelfCgroup)
	if err != nil {
		return "", fmt.Errorf("cgroup: read self membership: %w", err)
	}
	rel, err := parseSelfCgroup(data)
	if err != nil {
		return "", err
	}
	return filepath.Join(h.root(), rel), nil
}

// parseSelfCgroup extracts the v2 path ("0::<path>") from a
// /proc/<pid>/cgroup listing; v1 controller lines are ignored.
func parseSelfCgroup(data []byte) (string, error) {
	for line := range bytes.Lines(data) {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(string(line)), "0::"); ok {
			return rest, nil
		}
	}
	return "", errors.New("cgroup: no v2 entry in cgroup membership")
}

// Create makes a fresh cgroup named name with the named controllers
// enabled for it in its parent's subtree_control. The parent is
// found by walking from the caller's own cgroup upward to Root,
// taking the first directory that accepts both the creation and the
// controllers: placement is governed by the kernel's delegation
// boundary — only a directory on self's ancestry can receive this
// process's children, so no other candidate is considered no matter
// how writable — and the kernel's no-internal-process rule means a
// directory holding member processes (typically self's own leaf)
// refuses domain controllers, sending the walk one level up. A
// candidate where name already exists refuses outright rather than
// walking on: a stale twin from a crashed run must surface, never be
// shadowed. Controllers enabled in the parent stay enabled after
// Delete — withdrawal would race sibling cgroups. Note the walk can
// (and by the no-internal-process rule usually must) place the new
// cgroup outside the caller's own leaf, so a supervisor killing the
// caller's cgroup does not reach it — the caller's kill path owns
// that tie. The enabled set always includes a domain controller
// (withDomain): a thread-capable set alone would turn the parent
// into a thread root whose children can host no process.
func (h *Hierarchy) Create(name string, controllers []string) (*Cgroup, error) {
	controllers = withDomain(controllers)
	self, err := h.SelfDir()
	if err != nil {
		return nil, err
	}
	// A process vacate moved into a supervisor leaf is still the
	// delegated cgroup's tenant: its cgroups are the leaf's siblings,
	// never its children.
	if filepath.Base(self) == supervisorLeaf {
		self = filepath.Dir(self)
	}
	root := h.root()
	var firstErr error
	for dir := self; strings.HasPrefix(dir, root); dir = filepath.Dir(dir) {
		child := filepath.Join(dir, name)
		err := os.Mkdir(child, 0o755)
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("cgroup: create %s: %w", child, err)
		}
		if err == nil {
			cerr := enableControllers(dir, controllers)
			if cerr == nil {
				return &Cgroup{Dir: child}, nil
			}
			// A directory we cannot even abandon cleanly is a real
			// anomaly, not a candidate to walk past.
			if rerr := os.Remove(child); rerr != nil {
				return nil, fmt.Errorf("cgroup: abandon %s: %w", child, errors.Join(cerr, rerr))
			}
			err = cerr
		}
		if firstErr == nil {
			firstErr = err
		}
		if dir == root {
			break
		}
	}
	return nil, fmt.Errorf("cgroup: create %s: %w: %w", name, ErrNoAncestryBase, firstErr)
}

// ErrNoAncestryBase marks Create's ordinary refusal — every
// directory on self's cgroup ancestry declined the creation or the
// controllers — as distinct from an anomaly (membership unreadable,
// an abandoned directory irremovable), so a caller can fall back to
// another accounting without matching error text.
var ErrNoAncestryBase = errors.New("no directory on self's ancestry accepts it")

// domainControllers are the cgroup v2 controllers that make a cgroup
// a domain; the others (cpu, cpuset, pids) are thread-capable. A
// parent whose subtree_control names thread-capable controllers only
// becomes an implicit thread root, after which its children are
// domain-invalid and can host no process, and no domain controller
// can be enabled there again — so a request naming no domain
// controller is completed with memory before the write. The parent
// then accounts memory for every child it has, permanently: the cost
// of keeping it a domain.
var domainControllers = map[string]bool{"memory": true, "io": true, "hugetlb": true, "rdma": true, "misc": true}

// withDomain returns controllers with memory added when none of them
// is a domain controller.
func withDomain(controllers []string) []string {
	for _, c := range controllers {
		if domainControllers[c] {
			return controllers
		}
	}
	return append([]string{"memory"}, controllers...)
}

// enableControllers ensures each named controller is listed in dir's
// cgroup.subtree_control, enabling the missing ones in one write.
// One write, deliberately: enabling only thread-capable controllers
// (pids, cpu) first would make dir an implicit thread root, after
// which the kernel refuses every domain controller (memory) with
// EOPNOTSUPP. Already-enabled controllers need no write, so a base
// whose subtree_control is not writable still serves when its state
// is already right. A refusal with EBUSY — dir holds member
// processes, which cgroup v2 forbids beside child controllers —
// vacates dir into its supervisor leaf and asks once more: the
// delegation pattern for a cgroup that holds its own delegatee (a
// systemd scope, a container's namespace root).
func enableControllers(dir string, controllers []string) error {
	ctlPath := filepath.Join(dir, "cgroup.subtree_control")
	data, err := os.ReadFile(ctlPath)
	if err != nil {
		return fmt.Errorf("cgroup: read subtree_control: %w", err)
	}
	enabled := strings.Fields(string(data))
	var missing []string
	for _, c := range controllers {
		if !slices.Contains(enabled, c) {
			missing = append(missing, "+"+c)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	err = writeExistingFile(ctlPath, strings.Join(missing, " "))
	if errors.Is(err, unix.EBUSY) {
		if verr := vacate(dir); verr != nil {
			return fmt.Errorf("cgroup: enable controllers %v in %s: %w (vacating it: %v)", controllers, dir, err, verr)
		}
		err = writeExistingFile(ctlPath, strings.Join(missing, " "))
	}
	if err != nil {
		return fmt.Errorf("cgroup: enable controllers %v in %s: %w", controllers, dir, err)
	}
	return nil
}

// supervisorLeaf is the child cgroup a vacated cgroup's member
// processes move into.
const supervisorLeaf = ".supervisor"

// vacate moves every member process of dir into a leaf child so that
// controllers can be enabled for dir's children. Every member, not
// only this process: a namespace root holds a container's init beside
// us and a delegated scope may hold our parent. Membership is live —
// a member may exit between the listing and its move (ESRCH: gone,
// not an error) and forks may arrive — so the listing is re-read
// until it comes back empty, bounded so a cgroup gaining members
// faster than they move reports that rather than spinning. Kernel
// precondition: write access to dir and the leaf's cgroup.procs (the
// delegation the caller already holds).
func vacate(dir string) error {
	leaf := filepath.Join(dir, supervisorLeaf)
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", leaf, err)
	}
	for attempt := 0; attempt < 100; attempt++ {
		pids, err := procsAt(dir)
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			return nil
		}
		for _, pid := range pids {
			err := writeExistingFile(filepath.Join(leaf, "cgroup.procs"), strconv.Itoa(pid))
			if err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("move process %d out of %s: %w", pid, dir, err)
			}
		}
	}
	return fmt.Errorf("%s keeps gaining member processes faster than they can be moved", dir)
}

// defaultFreezeTimeout bounds the whole freeze-completion wait in
// Kill's fallback path — one deadline shared across every subtree
// directory, not per directory. Freezing settles in milliseconds on
// healthy hosts; the bound exists so a kernel that never reports
// frozen surfaces as an error instead of a hang.
const defaultFreezeTimeout = 5 * time.Second

// Cgroup is one created cgroup v2 directory.
type Cgroup struct {
	Dir string
	// FreezeTimeout overrides defaultFreezeTimeout when positive.
	FreezeTimeout time.Duration
}

// OpenFD opens the cgroup directory for CLONE_INTO_CGROUP
// (SysProcAttr.UseCgroupFD/CgroupFD): the child is born inside the
// cgroup, bounded from its first instruction, with no post-start
// migration — rootless setups cannot migrate across the delegation
// boundary anyway. Kernel >= 5.7 (clone3 with CLONE_INTO_CGROUP).
// The caller must keep the *os.File live (runtime.KeepAlive) until
// the child has started — its finalizer would close the fd and let
// the number be reused, cloning the child into an arbitrary cgroup —
// and close it afterwards. The fd is close-on-exec: the sandboxed
// process must not inherit a handle to its own cgroup, which would
// let it rewrite its bounds.
func (c *Cgroup) OpenFD() (*os.File, error) {
	f, err := os.OpenFile(c.Dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("cgroup: open %s: %w", c.Dir, err)
	}
	return f, nil
}

// SetMemoryMax writes the hard memory limit (memory.max, in bytes).
// Fails when the memory controller is not enabled for this cgroup.
func (c *Cgroup) SetMemoryMax(bytes uint64) error {
	return c.setResource("memory.max", strconv.FormatUint(bytes, 10))
}

// SetPidsMax writes the process-count limit (pids.max). Fails when
// the pids controller is not enabled for this cgroup.
func (c *Cgroup) SetPidsMax(n uint64) error {
	return c.setResource("pids.max", strconv.FormatUint(n, 10))
}

func (c *Cgroup) setResource(name, value string) error {
	if err := writeExistingFile(filepath.Join(c.Dir, name), value); err != nil {
		return fmt.Errorf("cgroup: set %s: %w", name, err)
	}
	return nil
}

// Procs returns the PIDs currently in the cgroup (this directory
// only, not descendants).
func (c *Cgroup) Procs() ([]int, error) {
	return procsAt(c.Dir)
}

func procsAt(dir string) ([]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil, fmt.Errorf("cgroup: read procs: %w", err)
	}
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("cgroup: bad pid %q in procs: %w", f, err)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// Kill terminates every process in the cgroup's subtree by the
// strongest means the kernel affords: a cgroup.kill write (kernel >=
// 5.14), which the kernel applies atomically to the whole subtree;
// else freeze-then-drain over every subtree directory. Any
// cgroup.kill failure falls back — the fallback covers the same
// subtree — and a fallback failure reports both errors.
func (c *Cgroup) Kill() error {
	killErr := writeExistingFile(filepath.Join(c.Dir, "cgroup.kill"), "1")
	if killErr == nil {
		return nil
	}
	if err := c.freezeKill(); err != nil {
		return errors.Join(fmt.Errorf("cgroup: kill: %w", killErr), err)
	}
	return nil
}

// freezeKill freezes the group (kernel >= 5.2), waits for the freeze
// to complete, SIGKILLs every member across the subtree, and thaws.
// The completed freeze is what makes the drain impossible to outrun
// by forking: the cgroup.freeze write returns before freezing
// finishes, so the member snapshot is taken only after cgroup.events
// reports frozen — from then on no member can clone (or create
// descendant cgroups, so the subtree walked here is stable), SIGKILL
// is deliverable to frozen tasks, and the thaw lets them die. The
// freeze propagates to descendants, and the drain visits every
// descendant directory's procs, matching cgroup.kill's subtree
// coverage. A member already gone (ESRCH) is not an error. A drain
// failure leaves the group frozen: holding a stopped group is
// strictly safer than thawing what could not be killed.
func (c *Cgroup) freezeKill() error {
	freeze := filepath.Join(c.Dir, "cgroup.freeze")
	if err := writeExistingFile(freeze, "1"); err != nil {
		return fmt.Errorf("cgroup: freeze: %w", err)
	}
	timeout := c.FreezeTimeout
	if timeout <= 0 {
		timeout = defaultFreezeTimeout
	}
	deadline := time.Now().Add(timeout)
	if err := waitFrozen(c.Dir, deadline); err != nil {
		return err
	}
	dirs, err := c.subtreeDirs()
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		if dir == c.Dir {
			continue
		}
		if err := waitFrozen(dir, deadline); err != nil {
			return err
		}
	}
	for _, dir := range dirs {
		pids, err := procsAt(dir)
		if err != nil {
			return err
		}
		for _, pid := range pids {
			if err := unix.Kill(pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("cgroup: kill pid %d: %w", pid, err)
			}
		}
	}
	if err := writeExistingFile(freeze, "0"); err != nil {
		return fmt.Errorf("cgroup: thaw: %w", err)
	}
	return nil
}

// subtreeDirs lists the cgroup directory and every descendant
// cgroup directory.
func (c *Cgroup) subtreeDirs() ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(c.Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cgroup: walk subtree: %w", err)
	}
	return dirs, nil
}

// waitFrozen polls dir's cgroup.events until it reports "frozen 1",
// bounded by the shared deadline so a kernel that never settles
// surfaces as an error instead of a hang. Zombies do not delay it:
// the group counts as frozen once every live task is.
func waitFrozen(dir string, deadline time.Time) error {
	events := filepath.Join(dir, "cgroup.events")
	for delay := 50 * time.Microsecond; ; {
		data, err := os.ReadFile(events)
		if err != nil {
			return fmt.Errorf("cgroup: read events: %w", err)
		}
		if eventsFrozen(data) {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("cgroup: freeze did not complete within the timeout")
		}
		time.Sleep(delay)
		if delay < 10*time.Millisecond {
			delay *= 2
		}
	}
}

// eventsFrozen reports whether a cgroup.events listing carries
// "frozen 1".
func eventsFrozen(data []byte) bool {
	for line := range bytes.Lines(data) {
		f := strings.Fields(string(line))
		if len(f) == 2 && f[0] == "frozen" && f[1] == "1" {
			return true
		}
	}
	return false
}

// Counters are the kernel's own accounting of a cgroup: the peak
// memory use, the processes the memory bound killed (memory.events
// oom_kill), and the forks the process bound refused (pids.events
// max). A counter whose file the cgroup does not carry (a controller
// not enabled for it) reads as zero.
type Counters struct {
	MemoryPeak  uint64
	OOMKills    uint64
	ForksDenied uint64
}

// Counters reads the cgroup's accounting. The directory outlives the
// process until Delete, so the final counts are readable after the
// process has been reaped; a descendant still dying at that moment
// can move the event counters by a little afterwards. memory.peak
// exists since kernel 5.19 — on an older kernel MemoryPeak reads as
// zero, which the caller cannot tell from an unused cgroup.
func (c *Cgroup) Counters() (Counters, error) {
	var ct Counters
	var err error
	if ct.MemoryPeak, err = c.readOptionalUint("memory.peak"); err != nil {
		return ct, err
	}
	if ct.OOMKills, err = c.readOptionalKey("memory.events", "oom_kill"); err != nil {
		return ct, err
	}
	if ct.ForksDenied, err = c.readOptionalKey("pids.events", "max"); err != nil {
		return ct, err
	}
	return ct, nil
}

func (c *Cgroup) readOptionalUint(name string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(c.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cgroup: read %s: %w", name, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cgroup: parse %s: %w", name, err)
	}
	return n, nil
}

func (c *Cgroup) readOptionalKey(name, key string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(c.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cgroup: read %s: %w", name, err)
	}
	for line := range bytes.Lines(data) {
		f := strings.Fields(string(line))
		if len(f) == 2 && f[0] == key {
			n, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("cgroup: parse %s %s: %w", name, key, err)
			}
			return n, nil
		}
	}
	return 0, nil
}

// Delete removes the cgroup directory. The kernel refuses (EBUSY)
// while member processes remain, including unreaped zombies — kill
// and wait first — and, briefly, while it finishes offlining a
// just-emptied cgroup; that transient refusal is retried for up to
// half a second before it is reported.
func (c *Cgroup) Delete() error {
	var err error
	for attempt := 0; attempt < 50; attempt++ {
		err = os.Remove(c.Dir)
		if !errors.Is(err, unix.EBUSY) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("cgroup: delete: %w", err)
	}
	return nil
}

// writeExistingFile writes value to an existing file, never creating
// one: on cgroupfs the file's existence is the kernel saying the
// knob is available, so a missing file must surface as ErrNotExist —
// and the same holds on test fixture trees, which is why every
// resource write goes through here rather than os.WriteFile.
func writeExistingFile(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(value)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
