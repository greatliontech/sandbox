//go:build linux

package nslinux

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const blockHelperEnv = "NSLINUX_BLOCK_HELPER"

// TestMain doubles as a blocking child for the kill tests: with the
// helper env set the binary parks on stdin until it is killed.
func TestMain(m *testing.M) {
	if os.Getenv(blockHelperEnv) == "1" {
		var buf [1]byte
		os.Stdin.Read(buf[:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// blockedChild starts a copy of the test binary that blocks until
// killed, returning the command with its stdin held open.
func blockedChild(t *testing.T) *exec.Cmd {
	t.Helper()
	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), blockHelperEnv+"=1")
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close() })
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill() })
	return child
}

// waitKilled asserts the child dies by SIGKILL within a bound, so a
// drain that never signals fails in seconds instead of hanging into
// the test binary's panic timeout.
func waitKilled(t *testing.T, c *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("child not killed within 5s")
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child.Wait: %v", err)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != unix.SIGKILL {
		t.Errorf("every subtree member must die by SIGKILL, wait status %v", ee)
	}
}

// fixtureHierarchy builds a Hierarchy over a temp tree. selfPath is
// the v2-relative cgroup the fake /proc/self/cgroup reports.
func fixtureHierarchy(t *testing.T, selfPath string) *Hierarchy {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "cg")
	if err := os.MkdirAll(filepath.Join(root, selfPath), 0o755); err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(base, "mounts")
	if err := os.WriteFile(mounts, []byte("cgroup2 "+root+" cgroup2 rw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	selfCg := filepath.Join(base, "self-cgroup")
	if err := os.WriteFile(selfCg, []byte("0::"+selfPath+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &Hierarchy{Root: root, ProcMounts: mounts, ProcSelfCgroup: selfCg}
}

// subtreeControl seeds a cgroup.subtree_control file at dir with the
// given enabled-controller list.
func subtreeControl(t *testing.T, dir, enabled string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(enabled), 0o644); err != nil {
		t.Fatal(err)
	}
}

// restrict chmods path and restores a writable mode at cleanup so
// TempDir removal succeeds. Tests using it are skipped as root —
// permission fixtures do not bind there; that is a stated coverage
// cap for root-run CI, not silent.
func restrict(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-denial fixtures do not bind as root")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o755) })
}

func TestMountsHaveCgroup2(t *testing.T) {
	cases := []struct {
		name   string
		mounts string
		root   string
		want   bool
	}{
		{"present", "proc /proc proc rw 0 0\ncgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n", "/sys/fs/cgroup", true},
		{"absent", "proc /proc proc rw 0 0\n", "/sys/fs/cgroup", false},
		{"v1 only", "cgroup /sys/fs/cgroup/memory cgroup rw,memory 0 0\n", "/sys/fs/cgroup", false},
		{"elsewhere", "cgroup2 /mnt/cg cgroup2 rw 0 0\n", "/sys/fs/cgroup", false},
		{"empty", "", "/sys/fs/cgroup", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mountsHaveCgroup2([]byte(tc.mounts), tc.root); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMountedNormalizesRoot(t *testing.T) {
	h := fixtureHierarchy(t, "/a")
	h.Root += "/" // caller spelling must not defeat the compare
	mounted, err := h.Mounted()
	if err != nil {
		t.Fatal(err)
	}
	if !mounted {
		t.Error("want mounted with a trailing-slash Root")
	}
}

func TestParseSelfCgroup(t *testing.T) {
	got, err := parseSelfCgroup([]byte("0::/user.slice/user-1000.slice/session-2.scope\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "/user.slice/user-1000.slice/session-2.scope"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseSelfCgroupSkipsV1Lines(t *testing.T) {
	data := "12:memory:/legacy\n1:name=systemd:/legacy\n0::/unified\n"
	got, err := parseSelfCgroup([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if got != "/unified" {
		t.Errorf("got %q, want /unified", got)
	}
}

func TestParseSelfCgroupNoV2Entry(t *testing.T) {
	if _, err := parseSelfCgroup([]byte("12:memory:/legacy\n")); err == nil {
		t.Fatal("want error for membership without a v2 entry")
	}
}

func TestCreateAtSelfWhenItAcceptsControllers(t *testing.T) {
	h := fixtureHierarchy(t, "/a")
	subtreeControl(t, filepath.Join(h.Root, "a"), "memory\n")

	cg, err := h.Create("s1", []string{"memory", "pids"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(h.Root, "a", "s1"); cg.Dir != want {
		t.Errorf("dir %q, want %q", cg.Dir, want)
	}
	// memory was already enabled; only pids needed a write.
	data, err := os.ReadFile(filepath.Join(h.Root, "a", "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "+pids" {
		t.Errorf("subtree_control = %q, want %q", got, "+pids")
	}
}

func TestCreateSkipsWriteWhenControllersAlreadyEnabled(t *testing.T) {
	// Enabled controllers need no write — which is what lets a base
	// serve even when its subtree_control is not writable. The pin
	// is content identity: every requested controller is already
	// listed, so the file must come through Create byte-identical
	// (any write would truncate it to a "+..." op). Unlike a
	// permission fixture, this holds when the tests run as root.
	h := fixtureHierarchy(t, "/a")
	base := filepath.Join(h.Root, "a")
	const enabled = "memory pids\n"
	subtreeControl(t, base, enabled)

	if _, err := h.Create("s1", []string{"memory", "pids"}); err != nil {
		t.Fatalf("enabled controllers must need no write: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(base, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != enabled {
		t.Errorf("subtree_control = %q, want untouched %q", data, enabled)
	}
}

func TestCreateWalksPastControllerRefusal(t *testing.T) {
	// Self's own dir accepts the mkdir but cannot deliver the
	// controllers (no subtree_control — the shape a process-holding
	// leaf presents via EBUSY on real cgroupfs). The walk must move
	// to the parent and remove the abandoned dir.
	h := fixtureHierarchy(t, "/a/b")
	subtreeControl(t, filepath.Join(h.Root, "a"), "memory pids\n")

	cg, err := h.Create("s1", []string{"memory"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(h.Root, "a", "s1"); cg.Dir != want {
		t.Errorf("dir %q, want %q", cg.Dir, want)
	}
	if _, err := os.Stat(filepath.Join(h.Root, "a", "b", "s1")); !errors.Is(err, os.ErrNotExist) {
		t.Error("abandoned dir at the refusing base must be removed")
	}
}

func TestCreateStaysOnAncestry(t *testing.T) {
	// A writable directory OFF the ancestry must never be selected:
	// placement is governed by the delegation boundary, and only
	// ancestors can receive this process's children.
	h := fixtureHierarchy(t, "/a/b")
	if err := os.MkdirAll(filepath.Join(h.Root, "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	subtreeControl(t, filepath.Join(h.Root, "other"), "memory\n")
	subtreeControl(t, filepath.Join(h.Root, "a"), "memory\n")
	restrict(t, filepath.Join(h.Root, "a", "b"), 0o555)

	cg, err := h.Create("s1", []string{"memory"})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(h.Root, "a", "s1"); cg.Dir != want {
		t.Errorf("dir %q, want %q", cg.Dir, want)
	}
	if _, err := os.Stat(filepath.Join(h.Root, "other", "s1")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a non-ancestor directory must never receive the cgroup")
	}
}

func TestCreateFailsWhenNoAncestryDirAccepts(t *testing.T) {
	h := fixtureHierarchy(t, "/a/b")
	restrict(t, filepath.Join(h.Root, "a", "b"), 0o555)
	restrict(t, filepath.Join(h.Root, "a"), 0o555)
	restrict(t, h.Root, 0o555)

	if _, err := h.Create("s1", nil); err == nil {
		t.Fatal("want error when no ancestry directory accepts creation")
	}
}

func TestCreateRefusesExistingName(t *testing.T) {
	h := fixtureHierarchy(t, "/a")
	subtreeControl(t, filepath.Join(h.Root, "a"), "")
	if err := os.Mkdir(filepath.Join(h.Root, "a", "s1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Create("s1", nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("a stale twin must surface, never be shadowed by walking on; got %v", err)
	}
}

func TestAvailable(t *testing.T) {
	t.Run("self accepts", func(t *testing.T) {
		h := fixtureHierarchy(t, "/a")
		subtreeControl(t, filepath.Join(h.Root, "a"), "memory pids\n")
		ok, err := h.Available([]string{"memory", "pids"})
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Error("want available")
		}
		// The dry-run cgroup must not linger.
		entries, err := os.ReadDir(filepath.Join(h.Root, "a"))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				t.Errorf("dry-run residue: %s", e.Name())
			}
		}
	})
	t.Run("not mounted", func(t *testing.T) {
		h := fixtureHierarchy(t, "/a")
		subtreeControl(t, filepath.Join(h.Root, "a"), "memory\n")
		if err := os.WriteFile(h.ProcMounts, []byte("proc /proc proc rw 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ok, err := h.Available([]string{"memory"})
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("want unavailable without a cgroup2 mount")
		}
	})
	t.Run("controllers undeliverable", func(t *testing.T) {
		// Placement alone is not availability: a tree that accepts
		// mkdir everywhere but can enable the controllers nowhere
		// must answer false, so the caller takes the rlimit fallback
		// instead of failing Start.
		h := fixtureHierarchy(t, "/a")
		ok, err := h.Available([]string{"memory"})
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Error("want unavailable when controllers cannot be enabled")
		}
	})
	t.Run("mount table unreadable is an anomaly", func(t *testing.T) {
		h := fixtureHierarchy(t, "/a")
		if err := os.Remove(h.ProcMounts); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Available(nil); err == nil {
			t.Error("want error when the mount table cannot be read")
		}
	})
	t.Run("membership unreadable is an anomaly", func(t *testing.T) {
		// A mount table showing cgroup2 with an unreadable own
		// membership is an inconsistency, not "no cgroups here" —
		// answering (false, nil) would send the caller to rlimit
		// bounds on a host where cgroups work.
		h := fixtureHierarchy(t, "/a")
		subtreeControl(t, filepath.Join(h.Root, "a"), "memory\n")
		if err := os.Remove(h.ProcSelfCgroup); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Available([]string{"memory"}); err == nil {
			t.Error("want error when own membership cannot be read")
		}
	})
	t.Run("repeat and concurrent calls never collide", func(t *testing.T) {
		// Probe names are unique per call, so a residue or a
		// concurrent probe can never make Create refuse EEXIST and
		// turn availability falsely false.
		if probeName() == probeName() {
			t.Fatal("probe names must be unique per call")
		}
		h := fixtureHierarchy(t, "/a")
		subtreeControl(t, filepath.Join(h.Root, "a"), "memory\n")
		for range 2 {
			ok, err := h.Available([]string{"memory"})
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Error("want available on every call")
			}
		}
	})
}

func cgroupFixture(t *testing.T, files map[string]string) *Cgroup {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Cgroup{Dir: dir}
}

func TestSetMemoryMaxWritesLimit(t *testing.T) {
	cg := cgroupFixture(t, map[string]string{"memory.max": "max\n"})
	if err := cg.SetMemoryMax(1 << 20); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(cg.Dir, "memory.max"))
	if got := string(data); got != "1048576" {
		t.Errorf("memory.max = %q, want 1048576", got)
	}
}

func TestSetPidsMaxWritesLimit(t *testing.T) {
	cg := cgroupFixture(t, map[string]string{"pids.max": "max\n"})
	if err := cg.SetPidsMax(64); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(cg.Dir, "pids.max"))
	if got := string(data); got != "64" {
		t.Errorf("pids.max = %q, want 64", got)
	}
}

func TestResourceWriteFailsWhenControllerFileAbsent(t *testing.T) {
	// On cgroupfs a knob's file existing is the kernel saying the
	// controller is enabled; a write must never fabricate the file
	// and report a bound that nothing enforces.
	cg := cgroupFixture(t, nil)
	if err := cg.SetMemoryMax(1 << 20); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want ErrNotExist for absent memory.max, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(cg.Dir, "memory.max")); !errors.Is(err, os.ErrNotExist) {
		t.Error("write must not create memory.max")
	}
}

func TestProcsParsesPids(t *testing.T) {
	cg := cgroupFixture(t, map[string]string{"cgroup.procs": "12\n34\n"})
	pids, err := cg.Procs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pids) != 2 || pids[0] != 12 || pids[1] != 34 {
		t.Errorf("pids = %v, want [12 34]", pids)
	}
}

func TestProcsEmpty(t *testing.T) {
	cg := cgroupFixture(t, map[string]string{"cgroup.procs": ""})
	pids, err := cg.Procs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pids) != 0 {
		t.Errorf("pids = %v, want none", pids)
	}
}

func TestEventsFrozen(t *testing.T) {
	cases := []struct {
		events string
		want   bool
	}{
		{"populated 1\nfrozen 1\n", true},
		{"populated 1\nfrozen 0\n", false},
		{"populated 1\n", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := eventsFrozen([]byte(tc.events)); got != tc.want {
			t.Errorf("eventsFrozen(%q) = %v, want %v", tc.events, got, tc.want)
		}
	}
}

func TestKillPrefersCgroupKill(t *testing.T) {
	// No freeze/events/procs fixtures: reaching the fallback would
	// error, so their absence also pins that the atomic path is
	// taken.
	cg := cgroupFixture(t, map[string]string{"cgroup.kill": ""})
	if err := cg.Kill(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(cg.Dir, "cgroup.kill"))
	if got := string(data); got != "1" {
		t.Errorf("cgroup.kill = %q, want 1", got)
	}
}

func TestKillFreezeDrainFallback(t *testing.T) {
	// No cgroup.kill: freeze, wait until the freeze completes,
	// SIGKILL every member across the subtree, thaw. A pid that is
	// already gone is not an error, and the drain delivers real
	// SIGKILLs — proven against live children alongside the ESRCH
	// pid, one of them in a descendant directory, since cgroup.kill
	// covers the subtree and the fallback must match.
	child := blockedChild(t)
	nested := blockedChild(t)

	cg := cgroupFixture(t, map[string]string{
		"cgroup.freeze": "0",
		"cgroup.events": "populated 1\nfrozen 1\n",
		"cgroup.procs":  "999999999\n" + strconv.Itoa(child.Process.Pid) + "\n",
	})
	sub := filepath.Join(cg.Dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"cgroup.events": "populated 1\nfrozen 1\n",
		"cgroup.procs":  strconv.Itoa(nested.Process.Pid) + "\n",
	} {
		if err := os.WriteFile(filepath.Join(sub, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := cg.Kill(); err != nil {
		t.Fatal(err)
	}

	for _, c := range []*exec.Cmd{child, nested} {
		waitKilled(t, c)
	}

	data, _ := os.ReadFile(filepath.Join(cg.Dir, "cgroup.freeze"))
	if got := string(data); got != "0" {
		t.Errorf("cgroup.freeze = %q, want thawed 0", got)
	}
}

func TestKillWaitsForFreezeCompletion(t *testing.T) {
	// Writing cgroup.freeze returns before the group is frozen; a
	// drain snapshotted early can miss a task mid-clone. The verb
	// must not proceed while cgroup.events reads frozen 0.
	// The member list is empty on purpose: every later stage of the
	// fallback then succeeds, so the only path to an error — and the
	// only thing this test can be passing on — is the wait itself.
	cg := cgroupFixture(t, map[string]string{
		"cgroup.freeze": "0",
		"cgroup.events": "populated 1\nfrozen 0\n",
		"cgroup.procs":  "",
	})
	cg.FreezeTimeout = 20 * time.Millisecond
	err := cg.Kill()
	if err == nil {
		t.Fatal("want error when the freeze never completes")
	}
	if !strings.Contains(err.Error(), "freeze did not complete") {
		t.Fatalf("error must name the incomplete freeze, got %v", err)
	}
}

func TestKillFreezesBeforeDraining(t *testing.T) {
	// The completed freeze must precede the drain — that ordering is
	// what makes the kill impossible to outrun by forking. A drain
	// failure after the freeze leaves the group frozen, which is the
	// observable proof of the order (and holding a stopped group is
	// strictly safer than thawing what could not be killed).
	cg := cgroupFixture(t, map[string]string{
		"cgroup.freeze": "0",
		"cgroup.events": "populated 1\nfrozen 1\n",
		"cgroup.procs":  "1\n",
	})
	restrict(t, filepath.Join(cg.Dir, "cgroup.procs"), 0o200) // unreadable: drain fails
	if err := cg.Kill(); err == nil {
		t.Fatal("want error when the member list cannot be read")
	}
	data, _ := os.ReadFile(filepath.Join(cg.Dir, "cgroup.freeze"))
	if got := string(data); got != "1" {
		t.Errorf("cgroup.freeze = %q at drain failure, want 1 (frozen first)", got)
	}
}

func TestKillFallsBackWhenCgroupKillRefuses(t *testing.T) {
	// A cgroup.kill that exists but refuses the write must not end
	// the kill: the fallback covers the same subtree. The refusing
	// fixture is a self-referential symlink (ELOOP on open, not
	// ErrNotExist) rather than a read-only file, so the pin holds
	// even when the tests run as root, which permission fixtures
	// cannot bind.
	cg := cgroupFixture(t, map[string]string{
		"cgroup.freeze": "0",
		"cgroup.events": "populated 1\nfrozen 1\n",
		"cgroup.procs":  "999999999\n",
	})
	if err := os.Symlink("cgroup.kill", filepath.Join(cg.Dir, "cgroup.kill")); err != nil {
		t.Fatal(err)
	}
	if err := cg.Kill(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(cg.Dir, "cgroup.freeze"))
	if got := string(data); got != "0" {
		t.Errorf("cgroup.freeze = %q, want thawed 0", got)
	}
}

func TestKillFailsWithoutKillOrFreeze(t *testing.T) {
	cg := cgroupFixture(t, nil)
	if err := cg.Kill(); err == nil {
		t.Fatal("want error when neither cgroup.kill nor cgroup.freeze exists")
	}
}

func TestOpenFDIsCloexecDirectoryFD(t *testing.T) {
	cg := cgroupFixture(t, nil)
	f, err := cg.OpenFD()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The sandboxed child must not inherit a handle to its own
	// cgroup — that would let it rewrite its bounds.
	fdFlags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Error("cgroup fd must be close-on-exec")
	}
}

func TestOpenFDRefusesNonDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cg := &Cgroup{Dir: file}
	if _, err := cg.OpenFD(); !errors.Is(err, unix.ENOTDIR) {
		t.Fatalf("want ENOTDIR for a non-directory, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	cg := cgroupFixture(t, nil)
	if err := cg.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cg.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Error("cgroup dir must be gone")
	}
}
