//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/elastic/go-seccomp-bpf/arch"
	"github.com/greatliontech/sandbox/internal/nslinux"
	"github.com/greatliontech/sandbox/internal/testdemand"
	"golang.org/x/sys/unix"
)

// worldTree is the static probe binary built once into a bare tree
// for the Root tests; empty when the build failed, with the reason.
var (
	worldTree         string
	worldTreeErr      error
	usernsUnavailable string // non-empty when the host cannot create user namespaces
)

const probeEnv = "SANDBOX_TEST_USERNS_PROBE"

// TestMain builds the world probe once (CGO_ENABLED=0, so the tree
// needs no libraries) into a tree shaped for the Root tests: the
// probe at /world, a marker file, and the directories the exact
// listing test expects. It also probes user-namespace creation
// directly — a clone of this binary under CLONE_NEWUSER running no
// tests — so the live tests skip only for that host capability and
// fail for everything else.
func TestMain(m *testing.M) {
	if os.Getenv(probeEnv) == "1" {
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "sandbox-tree-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "world"), "testdata/world/main.go")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		worldTreeErr = fmt.Errorf("building the world probe: %v\n%s", err, out)
	} else {
		for _, d := range []string{"etc", "grant-ro", "grant-rw", "run"} {
			if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
				worldTreeErr = err
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "etc", "tree-marker"), []byte("tree"), 0o644); err != nil {
			worldTreeErr = err
		}
		worldTree = dir
	}
	usernsUnavailable = probeUserns()
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// probeUserns reports why user namespaces are unavailable, or "".
// Only the kernel's refusals count (EPERM for a disabled or
// restricted feature, ENOSPC for an exhausted namespace budget); any
// other failure to run the probe is a broken harness and aborts the
// run rather than turning into a skip.
func probeUserns() string {
	probe := exec.Command(os.Args[0], "-test.run=^$")
	probe.Env = append(os.Environ(), probeEnv+"=1")
	probe.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := probe.CombinedOutput()
	if err == nil {
		return ""
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EINVAL) {
		return fmt.Sprintf("%v: %s", err, out)
	}
	fmt.Fprintf(os.Stderr, "user-namespace probe failed for a reason other than availability: %v\n%s", err, out)
	os.Exit(1)
	return ""
}

// requireUserns skips a Strong-row arm where the host cannot create
// user namespaces at all — unless SANDBOX_TEST_REQUIRE_USERNS demands
// the row, in which case a host that was meant to deliver it fails
// instead of skipping past every Strong-row arm.
func requireUserns(t testing.TB) {
	t.Helper()
	unavailable := ""
	if usernsUnavailable != "" {
		unavailable = "user namespaces are unavailable here: " + usernsUnavailable
	}
	testdemand.Live(t, "SANDBOX_TEST_REQUIRE_USERNS", unavailable)
}

// startOrSkip starts the sandbox where the host can create user
// namespaces (requireUserns says what happens where it cannot);
// every Start failure on a capable host is the test's to judge.
func startOrSkip(t *testing.T, sb Sandbox) {
	t.Helper()
	requireUserns(t)
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func requireTree(t *testing.T) {
	t.Helper()
	if worldTreeErr != nil {
		t.Fatal(worldTreeErr)
	}
}

// facts parses the probe's "key=value" lines.
func facts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}

// TestNamespaceIsolation is the core spike: a pure-Go, create-only sandbox must
// run a process in fresh PID and UTS namespaces with no cgo.
//
//   - pid=1 proves the new PID namespace (the process is its own init).
//   - the hostname proves the new UTS namespace + Sethostname.
//   - uid=0 proves the user namespace mapping (mapped root inside, real uid out).
//
// Each assertion is load-bearing: drop CLONE_NEWPID and pid!=1; drop the
// Sethostname and the hostname won't match; drop CLONE_NEWUSER + mappings and
// uid!=0.
func TestNamespaceIsolation(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}

	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:     "/bin/sh",
		Args:     []string{"-c", "echo pid=$$ uid=$(id -u) host=$(cat /proc/sys/kernel/hostname)"},
		Hostname: "spikebox",
		Stdout:   &out,
		Stderr:   &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)

	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}

	got := out.String()
	if es.Code != 0 {
		t.Fatalf("exit code = %d, output: %q", es.Code, got)
	}
	if !strings.Contains(got, "pid=1") {
		t.Errorf("PID namespace not isolated: want pid=1, output: %q", got)
	}
	if !strings.Contains(got, "uid=0") {
		t.Errorf("user namespace not mapped: want uid=0, output: %q", got)
	}
	if !strings.Contains(got, "host=spikebox") {
		t.Errorf("UTS namespace not isolated: want host=spikebox, output: %q", got)
	}
	if sb.Tier() != Strong {
		t.Errorf("Tier() = %v, want strong", sb.Tier())
	}
}

// TestExitCodePropagation checks a non-zero exit is reported, not swallowed.
func TestExitCodePropagation(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	sb, err := New(Spec{Exec: "/bin/sh", Args: []string{"-c", "exit 7"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if es.Code != 7 {
		t.Errorf("exit code = %d, want 7", es.Code)
	}
}

// worldFixture copies the world tree into a fresh directory and adds
// mount targets for the given host paths, so a test can shape its
// own tree without touching the shared fixture.
func worldFixture(t *testing.T, targets ...string) string {
	t.Helper()
	requireTree(t)
	tree := t.TempDir()
	if err := os.CopyFS(tree, os.DirFS(worldTree)); err != nil {
		t.Fatal(err)
	}
	for _, p := range targets {
		if err := os.MkdirAll(filepath.Join(tree, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return tree
}

// The Strong world under a Root: the tree is the whole visible root,
// read-only; the read-only grant is readable and not writable; the
// read-write grant and the rendezvous directory are writable, at
// their own paths; the working directory is inside the tree; no
// /proc is presented (nothing is mounted the caller did not state);
// the environment is empty when unstated; and none of it wrote into
// the tree itself, transiently or otherwise (mtimes included).
func TestRootWorld(t *testing.T) {
	roHost := t.TempDir()
	rwHost := t.TempDir()
	runHost := t.TempDir()
	if err := os.WriteFile(filepath.Join(roHost, "marker"), []byte("granted"), 0o644); err != nil {
		t.Fatal(err)
	}
	tree := worldFixture(t, roHost, rwHost, runHost)
	before := snapshot(t, tree)

	var out, errOut bytes.Buffer
	sb, err := New(Spec{
		Exec:       "/world",
		Args:       []string{roHost, rwHost, runHost},
		Root:       tree,
		WorkDir:    "/etc",
		Hostname:   "world",
		PathGrants: []PathGrant{{Path: roHost, Access: ReadOnly}, {Path: rwHost, Access: ReadWrite}},
		RuntimeDir: runHost,
		Stdout:     &out,
		Stderr:     &errOut,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if es.Code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", es.Code, errOut.String())
	}
	f := facts(out.String())
	if f["cwd"] != "/etc" {
		t.Errorf("cwd = %q, want /etc", f["cwd"])
	}
	// The three host paths live under one temp parent, which the
	// fixture materialized as one extra entry in the tree's root.
	wantRoot := "etc,grant-ro,grant-rw,run," + strings.SplitN(strings.TrimPrefix(roHost, "/"), "/", 2)[0] + ",world"
	if f["root"] != wantRoot {
		t.Errorf("root view = %q, want exactly %q", f["root"], wantRoot)
	}
	if f["env"] != "0" {
		t.Errorf("env = %s entries under a Root with none stated", f["env"])
	}
	if f["proc-hostname"] != `""` {
		t.Errorf("proc visible: hostname read %s", f["proc-hostname"])
	}
	if f["write-root-err"] != "true" || f["mkdir-root-err"] != "true" {
		t.Errorf("root writable: write-err=%s mkdir-err=%s", f["write-root-err"], f["mkdir-root-err"])
	}
	if f["ro-read"] != `"granted"` || f["ro-read-err"] != "false" || f["ro-write-err"] != "true" {
		t.Errorf("read-only grant: read=%s read-err=%s write-err=%s", f["ro-read"], f["ro-read-err"], f["ro-write-err"])
	}
	if f["rw-write-err"] != "false" {
		t.Errorf("read-write grant not writable")
	}
	if f["run-write-err"] != "false" {
		t.Errorf("rendezvous directory not writable")
	}
	if _, err := os.Stat(filepath.Join(rwHost, "probe")); err != nil {
		t.Errorf("read-write grant's write did not reach the host: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runHost, "sock")); err != nil {
		t.Errorf("rendezvous write did not reach the host: %v", err)
	}
	if after := snapshot(t, tree); after != before {
		t.Errorf("the tree was written:\nbefore: %s\nafter:  %s", before, after)
	}
}

// A Root world with nothing but the tree: the entrypoint comes from
// the tree and the working directory defaults to its root.
func TestRootWorldBare(t *testing.T) {
	requireTree(t)
	var out bytes.Buffer
	sb, err := New(Spec{Exec: "/world", Root: worldTree, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %v %+v %s", err, es, out.String())
	}
	f := facts(out.String())
	if f["cwd"] != "/" || f["root"] != "etc,grant-ro,grant-rw,run,world" {
		t.Errorf("bare world: cwd=%q root=%q", f["cwd"], f["root"])
	}
}

// Undeliverable intents refuse Start with ErrUndeliverable, naming the
// diagnosis, before anything is cloned.
func TestRootRefusesUndeliverable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dirHost := t.TempDir()   // its tree target is a symlink
	nested := t.TempDir()    // a grant whose tree-side parent is a symlink
	wrongKind := t.TempDir() // its tree target is a file
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	tree := worldFixture(t, filepath.Dir(dirHost), filepath.Dir(nested), filepath.Dir(wrongKind), outer, inner)
	if err := os.Symlink("/etc", filepath.Join(tree, dirHost)); err != nil {
		t.Fatal(err)
	}
	// The parent of nested's target is a symlink to a real directory
	// holding a real "data" entry: every component but the last is a
	// symlink's, which is the case a final-component check misses.
	nestedData := filepath.Join(nested, "data")
	if err := os.Mkdir(nestedData, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(tree, "elsewhere")
	if err := os.MkdirAll(filepath.Join(elsewhere, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(tree, nested)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, wrongKind), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		spec Spec
		want string // the diagnosis the refusal names
	}{
		"root is a file":           {Spec{Exec: "/world", Root: file}, "is not a directory"},
		"root missing":             {Spec{Exec: "/world", Root: filepath.Join(tree, "nope")}, "root"},
		"exec relative":            {Spec{Exec: "world", Root: tree}, "is not an absolute path"},
		"exec not in tree":         {Spec{Exec: "/absent", Root: tree}, "exec /absent is not in the tree"},
		"exec is a directory":      {Spec{Exec: "/etc", Root: tree}, "is a directory in the tree"},
		"workdir not in tree":      {Spec{Exec: "/world", Root: tree, WorkDir: "/nowhere"}, "workdir /nowhere is not in the tree"},
		"workdir not a directory":  {Spec{Exec: "/world", Root: tree, WorkDir: "/world"}, "is not a directory in the tree"},
		"grant has no target":      {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: t.TempDir()}}}, "has no target in the tree"},
		"grant target symlink":     {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: dirHost}}}, "passes through a symlink in the tree"},
		"grant parent symlink":     {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: nestedData}}}, "passes through a symlink in the tree (" + nested + ")"},
		"grant wrong kind":         {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: wrongKind}}}, "is a directory on the host but a file in the tree"},
		"grant absent on host":     {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: "/nonexistent-grant"}}}, "grant /nonexistent-grant"},
		"grant unclean":            {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: "/tmp/../tmp"}}}, "is not a clean absolute path"},
		"grants duplicate":         {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: outer, Access: ReadWrite}, {Path: outer, Access: ReadOnly}}}, "overlap"},
		"grants nested":            {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: outer}, {Path: inner}}}, "overlap"},
		"runtime dir over a grant": {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: outer, Access: ReadOnly}}, RuntimeDir: outer}, "overlap"},
		"runtime dir missing":      {Spec{Exec: "/world", Root: tree, RuntimeDir: t.TempDir()}, "runtime dir"},
		"grants overlap no root":   {Spec{Exec: "/bin/sh", PathGrants: []PathGrant{{Path: outer}, {Path: inner}}}, "overlap"},
		"grant of the root itself": {Spec{Exec: "/world", Root: tree, PathGrants: []PathGrant{{Path: "/"}}}, "is the root of the world"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sb, err := New(c.spec)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = sb.Start(context.Background())
			if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Start = %v, want ErrUndeliverable naming %q", err, c.want)
			}
		})
	}
}

// A world that cannot be composed inside the namespaces refuses Start
// with ErrUndeliverable and the reason, from either side of the
// sentinel: a composition step (a hostname the kernel refuses) and the
// exec itself (an entrypoint present but not executable).
func TestStartReportsCompositionFailure(t *testing.T) {
	requireTree(t)
	requireUserns(t)
	sb, err := New(Spec{Exec: "/world", Root: worldTree, Hostname: strings.Repeat("h", 300)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = sb.Start(context.Background())
	if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("hostname refusal: %v", err)
	}
	if sb.(*linuxSandbox).cmd != nil {
		t.Fatal("a hostname the kernel would refuse was cloned for")
	}

	tree := worldFixture(t)
	if err := os.Chmod(filepath.Join(tree, "world"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err = New(Spec{Exec: "/world", Root: tree})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = sb.Start(context.Background())
	if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "exec /world") {
		t.Fatalf("exec failure: %v", err)
	}
}

// The status pipe's shapes classify apart: nothing written is a death
// before exec, an intent reason before the sentinel is a refusal, an
// application reason before it is the row failing to apply, the
// sentinel alone is the target running, a reason after the sentinel
// is a failed exec; anything else is garbled.
func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		in     string
		want   initOutcome
		reason string
	}{
		{"", initDied, ""},
		{statusExecing, initExeced, ""},
		{statusFailed + "chdir /x: no such file or directory\n", initRefused, "chdir /x: no such file or directory"},
		{statusApplyFailed + "pivot_root: EPERM\n", initApplyFailed, "pivot_root: EPERM"},
		{statusExecing + statusApplyFailed + "x", initGarbled, ""},
		{statusExecing + statusFailed + "exec /x: permission denied", initRefused, "exec /x: permission denied"},
		{"junk", initGarbled, ""},
		{statusExecing + statusExecing, initGarbled, ""},
	}
	for _, c := range cases {
		got, reason := classifyStatus([]byte(c.in))
		if got != c.want || reason != c.reason {
			t.Errorf("classifyStatus(%q) = %v %q, want %v %q", c.in, got, reason, c.want, c.reason)
		}
	}
}

// Without a Root the world is the host's, in a private mount
// namespace, with the host environment inherited; a read-only grant
// is still delivered throughout its subtree — its submounts included
// — while the host keeps writing.
func TestGrantsWithoutRoot(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	ro := t.TempDir()
	rw := t.TempDir()
	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:       "/bin/sh",
		Args:       []string{"-c", fmt.Sprintf("touch %s/x 2>/dev/null && echo ro=writable || echo ro=readonly; touch %s/x && echo rw=writable; [ -n \"$HOME\" ] && echo env=inherited", ro, rw)},
		PathGrants: []PathGrant{{Path: ro, Access: ReadOnly}, {Path: rw, Access: ReadWrite}},
		Stdout:     &out,
		Stderr:     &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %v %+v %s", err, es, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "ro=readonly") || !strings.Contains(got, "rw=writable") || !strings.Contains(got, "env=inherited") {
		t.Fatalf("grants without root: %q", got)
	}
	if err := os.WriteFile(filepath.Join(ro, "host"), nil, 0o644); err != nil {
		t.Fatalf("the host lost write access to its own directory: %v", err)
	}

	// A subtree with a submount: /dev carries /dev/shm on most hosts.
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(info), " /dev/shm ") {
		t.Skip("/dev/shm is not a mount here; no submount to prove the recursion on")
	}
	out.Reset()
	sb, err = New(Spec{
		Exec:       "/bin/sh",
		Args:       []string{"-c", "touch /dev/shm/sandbox-probe 2>/dev/null && echo shm=writable || echo shm=readonly"},
		PathGrants: []PathGrant{{Path: "/dev", Access: ReadOnly}},
		Stdout:     &out,
		Stderr:     &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %v %+v %s", err, es, out.String())
	}
	if !strings.Contains(out.String(), "shm=readonly") {
		t.Fatalf("read-only grant left its submount writable: %q", out.String())
	}
}

// Start returns once the target is execed, not when it exits: the
// status pipe closes on exec. A payload that outlives Start by far
// pins it, and the caller's context then ends the run.
func TestStartReturnsAtExec(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	requireUserns(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sb, err := New(Spec{Exec: "/bin/sh", Args: []string{"-c", "sleep 30"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- sb.Start(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return while the payload was still running")
	}
	cancel()
	if es, err := sb.Wait(); err != nil || !es.Signaled {
		t.Fatalf("Wait after cancel: %v %+v", err, es)
	}
}

// snapshot lists every entry under dir with its mode, size, and
// modification time — the evidence that a run wrote nothing into the
// tree: a directory created and removed again still bumps its
// parent's mtime.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		fmt.Fprintf(&b, "%s %v %d %d\n", rel, info.Mode(), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Canonical paths, not stated spellings, are what the mount table
// records: a read-only grant stated through a symlinked host path,
// and a Root stated through a symlink, are still delivered read-only.
func TestSymlinkedSpellingsStillReadOnly(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:       "/bin/sh",
		Args:       []string{"-c", "touch " + link + "/x 2>/dev/null && echo grant=writable || echo grant=readonly"},
		PathGrants: []PathGrant{{Path: link, Access: ReadOnly}},
		Stdout:     &out,
		Stderr:     &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %v %+v %s", err, es, out.String())
	}
	if !strings.Contains(out.String(), "grant=readonly") {
		t.Fatalf("read-only grant through a symlinked host path: %q", out.String())
	}
	// Two spellings of one directory, or a link into another grant's
	// subtree, are overlapping intents however they are spelled.
	sub := filepath.Join(real, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, grants := range map[string][]PathGrant{
		"alias":       {{Path: real, Access: ReadWrite}, {Path: link, Access: ReadOnly}},
		"alias above": {{Path: sub, Access: ReadWrite}, {Path: link, Access: ReadOnly}},
	} {
		sb, err := New(Spec{Exec: "/bin/sh", Args: []string{"-c", "true"}, PathGrants: grants})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("%s: %v", name, err)
		}
	}

	roHost := t.TempDir()
	tree := worldFixture(t, roHost)
	treeLink := filepath.Join(t.TempDir(), "tree")
	if err := os.Symlink(tree, treeLink); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	sb, err = New(Spec{
		Exec:       "/world",
		Args:       []string{roHost},
		Root:       treeLink,
		PathGrants: []PathGrant{{Path: roHost, Access: ReadOnly}},
		Stdout:     &out,
		Stderr:     &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %v %+v %s", err, es, out.String())
	}
	if f := facts(out.String()); f["ro-write-err"] != "true" || f["write-root-err"] != "true" {
		t.Fatalf("symlinked Root: %q", out.String())
	}
}

// The entrypoint and working directory resolve inside the tree the
// way the pivoted process resolves them: through absolute symlinks
// re-rooted at the tree, through relative ones, and with ".." clamped
// at the tree — while a target the tree does not hold is refused.
func TestEntrypointResolvesInTree(t *testing.T) {
	tree := worldFixture(t)
	if err := os.MkdirAll(filepath.Join(tree, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(tree, "world"), filepath.Join(tree, "usr", "bin", "world")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin", filepath.Join(tree, "bin")); err != nil { // absolute, image-style
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, "usr", "local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin", filepath.Join(tree, "usr", "local", "bin")); err != nil { // absolute, below the top level
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(tree, "sbin")); err != nil { // relative, Debian-style
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../usr/bin/world", filepath.Join(tree, "etc", "escaper")); err != nil { // ".." past the root clamps
		t.Fatal(err)
	}
	for _, exec := range []string{"/bin/world", "/sbin/world", "/usr/local/bin/world", "/etc/escaper", "/usr/../usr/bin/world"} {
		t.Run(exec, func(t *testing.T) {
			var out bytes.Buffer
			sb, err := New(Spec{Exec: exec, Root: tree, WorkDir: "/bin", Stdout: &out, Stderr: &out})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			startOrSkip(t, sb)
			if es, err := sb.Wait(); err != nil || es.Code != 0 {
				t.Fatalf("Wait: %v %+v %s", err, es, out.String())
			}
			// The working directory is stated through the absolute symlink and
			// resolves, as the kernel reports it, to the real directory.
			if f := facts(out.String()); f["cwd"] != "/usr/bin" {
				t.Fatalf("cwd = %q", f["cwd"])
			}
		})
	}
	// ".." after a symlink applies to the link's target, not to the
	// spelled path: with /a/b -> /x/y the kernel runs /x/c for
	// "/a/b/../c" even when a decoy /a/c exists, and refuses when only
	// the decoy does.
	if err := os.MkdirAll(filepath.Join(tree, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, "x", "y"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/x/y", filepath.Join(tree, "a", "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "a", "c"), []byte("decoy"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := New(Spec{Exec: "/a/b/../c", Root: tree})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "exec /a/b/../c is not in the tree") {
		t.Fatalf("dotdot across a symlink with only the decoy present: %v", err)
	}
	if err := os.Link(filepath.Join(tree, "usr", "bin", "world"), filepath.Join(tree, "x", "c")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sb, err = New(Spec{Exec: "/a/b/../c", Root: tree, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("dotdot across a symlink: %v %+v %s", err, es, out.String())
	}

	if err := os.Symlink("/nowhere/world", filepath.Join(tree, "dangling")); err != nil {
		t.Fatal(err)
	}
	sb, err = New(Spec{Exec: "/dangling", Root: tree})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "exec /dangling is not in the tree") {
		t.Fatalf("dangling entrypoint: %v", err)
	}
}

// The Strong row's hardening, observed from inside a Root world: every
// capability set and the bounding set are empty even though the
// process is the namespace's mapped root, no_new_privs is set, and
// the syscalls the row denies fail with EPERM — the mount table, the
// namespace, its identity, and the observation primitives.
func TestStrongHardening(t *testing.T) {
	requireTree(t)
	var out bytes.Buffer
	sb, err := New(Spec{Exec: "/world", Root: worldTree, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %v %+v %s", err, es, out.String())
	}
	f := facts(out.String())
	if f["caps"] != "e0/0,p0/0,i0/0" {
		t.Errorf("capability sets = %s, want all empty", f["caps"])
	}
	if f["bounding"] != "0" {
		t.Errorf("bounding set holds %s capabilities, want 0", f["bounding"])
	}
	if f["nnp"] != "1 err=false" {
		t.Errorf("no_new_privs = %s, want 1", f["nnp"])
	}
	// Two kinds of witness: syscalls only the filter refuses (no
	// capability governs them, so their EPERM is the filter's alone)
	// and syscalls the capability drop already refuses, where the
	// filter is defense in depth.
	for _, sc := range []string{"unshare", "keyctl", "io_uring_setup", "perf_event_open", "process_vm_readv", "request_key", "clock_adjtime"} {
		if f[sc] != "operation not permitted" {
			t.Errorf("%s = %q, want EPERM from the filter", sc, f[sc])
		}
	}
	for _, sc := range []string{"sethostname", "mount", "ptrace"} {
		if f[sc] != "operation not permitted" {
			t.Errorf("%s = %q, want EPERM (capability drop, filter behind it)", sc, f[sc])
		}
	}
}

// A payload built for a foreign machine is refused before anything
// runs: the row runs the native ABI only, and the entrypoint's ELF
// header says so up front.
func TestForeignABIRefused(t *testing.T) {
	requireTree(t)
	foreign := map[string]string{"amd64": "386", "arm64": "arm"}[runtime.GOARCH]
	if foreign == "" {
		t.Skipf("no foreign 32-bit ABI to exercise on %s", runtime.GOARCH)
	}
	tree := worldFixture(t)
	build := exec.Command("go", "build", "-o", filepath.Join(tree, "world32"), "testdata/world/main.go")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH="+foreign)
	if out, err := build.CombinedOutput(); err != nil {
		// The toolchain cross-compiles every architecture it ships:
		// a failure is a broken harness, never a skip.
		t.Fatalf("cannot build the %s probe here: %v\n%s", foreign, err, out)
	}
	for name, spec := range map[string]Spec{
		"under a root": {Exec: "/world32", Root: tree},
		"host path":    {Exec: filepath.Join(tree, "world32")},
	} {
		sb, err := New(spec)
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		err = sb.Start(context.Background())
		if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "built for") {
			t.Fatalf("%s: foreign-machine entrypoint: %v, want ErrUndeliverable naming the machine", name, err)
		}
	}
}

// An entrypoint the parent cannot read — execute-only, as a shared
// tree owned elsewhere can be — still starts: execve needs no read
// permission, and the machine check refuses only what it read.
func TestExecOnlyEntrypointStarts(t *testing.T) {
	requireTree(t)
	if os.Geteuid() == 0 {
		t.Skip("root reads through permission bits")
	}
	tree := worldFixture(t)
	if err := os.Chmod(filepath.Join(tree, "world"), 0o111); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sb, err := New(Spec{Exec: "/world", Root: tree, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("exec-only entrypoint: %v %+v %s", err, es, out.String())
	}
}

// A native payload that switches ABI at run time — one int 0x80 call
// from a 64-bit program — is killed at that call by the arch guard,
// after running fine through the native ABI.
func TestForeignABICallKilled(t *testing.T) {
	requireTree(t)
	if runtime.GOARCH != "amd64" {
		t.Skip("the ABI-switching stub is amd64 assembly")
	}
	tree := worldFixture(t)
	build := exec.Command("go", "build", "-o", filepath.Join(tree, "abiswitch"), "./testdata/abiswitch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the ABI-switching stub: %v\n%s", err, out)
	}
	var out bytes.Buffer
	sb, err := New(Spec{Exec: "/abiswitch", Root: tree, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if !strings.Contains(out.String(), "alive") || !es.Signaled || es.Signal != syscall.SIGSYS {
		t.Fatalf("ABI switch ended %+v with output %q, want the native run then death by SIGSYS", es, out.String())
	}
}

// Every name the deny list spells exists on at least one supported
// architecture; the native policy assembles; and a table without a
// name simply omits it (the i386 table lacks kexec_file_load, the
// 64-bit tables lack the time64 spellings).
func TestPolicyNamesResolve(t *testing.T) {
	tables := []*arch.Info{arch.X86_64, arch.AARCH64, arch.I386, arch.ARM}
	for _, group := range strongDenied {
		for _, name := range group {
			found := false
			for _, tb := range tables {
				if _, ok := tb.SyscallNames[name]; ok {
					found = true
				}
			}
			if !found {
				t.Errorf("%s is not a syscall on any supported architecture", name)
			}
		}
	}
	native, err := arch.GetInfo("")
	if err != nil {
		t.Fatal(err)
	}
	pol := strongSeccompPolicy(native)
	if _, err := pol.Assemble(); err != nil {
		t.Fatalf("native policy does not assemble: %v", err)
	}
	for _, tb := range tables {
		pol := strongSeccompPolicy(tb)
		for _, g := range pol.Syscalls {
			for _, n := range g.Names {
				if _, ok := tb.SyscallNames[n]; !ok {
					t.Errorf("%s policy names %s, which %s lacks", tb.Name, n, tb.Name)
				}
			}
		}
	}
	i386 := strongSeccompPolicy(arch.I386)
	for _, g := range i386.Syscalls {
		for _, n := range g.Names {
			if n == "kexec_file_load" {
				t.Error("kexec_file_load kept in the i386 policy, where it does not exist")
			}
		}
	}
}

// Hardening does not depend on a Root: the host-view world is just as
// capability-free and filtered.
func TestHardeningWithoutRoot(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available")
	}
	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:   "/bin/sh",
		Args:   []string{"-c", "grep -E '^(CapEff|CapBnd|NoNewPrivs):' /proc/self/status | tr -d '\\t' | tr '\\n' ' '"},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %v %+v %s", err, es, out.String())
	}
	// The capability and no_new_privs lines are the load-bearing
	// witnesses; a "Seccomp:2" line would be inherited from any filter
	// the host already runs the tests under, so it proves nothing here.
	got := out.String()
	for _, want := range []string{"CapEff:0000000000000000", "CapBnd:0000000000000000", "NoNewPrivs:1"} {
		if !strings.Contains(got, want) {
			t.Errorf("status lacks %s: %q", want, got)
		}
	}
}

// Network is denied unless granted: the default world holds a
// loopback and nothing else and cannot dial out; a granted world
// shares the host's interfaces. Both halves need a host with an
// interface beyond loopback — on one without, neither assertion could
// tell a fresh namespace from the host's, so both skip.
func TestNetworkGrant(t *testing.T) {
	requireTree(t)
	host, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(host) < 2 {
		t.Skip("the host has no interface beyond loopback; a fresh namespace would look like the host")
	}
	run := func(network bool) map[string]string {
		var out bytes.Buffer
		sb, err := New(Spec{Exec: "/world", Root: worldTree, Network: network, Stdout: &out, Stderr: &out})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		startOrSkip(t, sb)
		if es, err := sb.Wait(); err != nil || es.Code != 0 {
			t.Fatalf("Wait: %v %+v %s", err, es, out.String())
		}
		return facts(out.String())
	}
	denied := run(false)
	if denied["ifaces"] != "lo" || denied["dial-err"] != "true" {
		t.Errorf("denied network: interfaces %q, dial-err %s; want lo alone and a failed dial", denied["ifaces"], denied["dial-err"])
	}
	if got := run(true)["ifaces"]; got == "lo" || got == "" {
		t.Errorf("granted network sees interfaces %q, want the host's", got)
	}
}

// cgroupPlacement says whether this host affords cgroup placement
// for the memory and pids controllers — a fact an arm that runs
// either way branches on; a probe that cannot answer is a broken
// harness.
func cgroupPlacement(t testing.TB) bool {
	t.Helper()
	available, err := placementSupported(context.Background(), nslinux.DefaultHierarchy())
	if err != nil {
		t.Fatalf("cgroup probe: %v", err)
	}
	return available
}

// requireCgroups skips an arm that needs cgroup placement where the
// host affords none — unless SANDBOX_TEST_REQUIRE_CGROUPS demands the
// arms, in which case the host fails instead.
func requireCgroups(t testing.TB) {
	t.Helper()
	if !cgroupPlacement(t) {
		testdemand.Live(t, "SANDBOX_TEST_REQUIRE_CGROUPS", "cgroup placement is unavailable here")
	}
}

// The two demands fail where the host cannot deliver and the variable
// is set, and skip where it is not: the wiring of each surface's
// unavailability into the one rule, pinned by forcing it.
func TestDemandsFailWhereTheHostCannot(t *testing.T) {
	prev := usernsUnavailable
	usernsUnavailable = "forced for the test"
	t.Cleanup(func() { usernsUnavailable = prev })
	t.Setenv("SANDBOX_TEST_REQUIRE_USERNS", "1")
	if r := testdemand.Observe(func(t testing.TB) { requireUserns(t) }); r.Ran || !strings.Contains(r.FailureText, "SANDBOX_TEST_REQUIRE_USERNS is set and user namespaces are unavailable here: forced for the test") {
		t.Errorf("a demanded Strong row the host cannot deliver: %+v", r)
	}
	t.Setenv("SANDBOX_TEST_REQUIRE_USERNS", "")
	if r := testdemand.Observe(func(t testing.TB) { requireUserns(t) }); r.Ran || r.FailureText != "" || !strings.Contains(r.SkipText, "forced for the test") {
		t.Errorf("an undemanded Strong row the host cannot deliver: %+v", r)
	}

	h := nslinux.DefaultHierarchy()
	key := placementKey(h)
	placements.mu.Lock()
	saved, had := placements.results[key]
	if placements.results == nil {
		placements.results = map[string]probeResult[bool]{}
	}
	placements.results[key] = probeResult[bool]{value: false}
	placements.mu.Unlock()
	t.Cleanup(func() {
		placements.mu.Lock()
		defer placements.mu.Unlock()
		if had {
			placements.results[key] = saved
		} else {
			delete(placements.results, key)
		}
	})
	t.Setenv("SANDBOX_TEST_REQUIRE_CGROUPS", "1")
	if r := testdemand.Observe(func(t testing.TB) { requireCgroups(t) }); r.Ran || !strings.Contains(r.FailureText, "SANDBOX_TEST_REQUIRE_CGROUPS is set and cgroup placement is unavailable here") {
		t.Errorf("demanded cgroup placement the host cannot deliver: %+v", r)
	}
	t.Setenv("SANDBOX_TEST_REQUIRE_CGROUPS", "")
	if r := testdemand.Observe(func(t testing.TB) { requireCgroups(t) }); r.Ran || r.FailureText != "" || r.SkipText == "" {
		t.Errorf("undemanded cgroup placement the host cannot deliver: %+v", r)
	}
}

// The memory bound stops a runaway allocator, and the run reports
// which accounting did it: under cgroups a kill counted in the
// cgroup's events, under rlimits an allocation refused and the
// payload's own failure (docs/specs/sandbox.md, "Bounded means
// bounded").
func TestMemoryBound(t *testing.T) {
	requireTree(t)
	cgroups := cgroupPlacement(t)
	if !cgroups {
		// The arm degrades to the rlimits row — unless the counters
		// were demanded of this host.
		testdemand.Degrade(t, "SANDBOX_TEST_REQUIRE_CGROUPS", "cgroup placement is unavailable here")
	}
	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:   "/world",
		Args:   []string{"hog"},
		Root:   worldTree,
		Limits: Limits{MemoryBytes: 64 << 20},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	st, err := sb.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if strings.Contains(out.String(), "hogged=256") {
		t.Fatalf("the hog finished under a 64 MiB bound (accounting %s)", st.Accounting)
	}
	if cgroups {
		if !strings.Contains(out.String(), "hog-start") {
			t.Fatalf("the payload never started under the cgroup bound: %+v %q", es, out.String())
		}
		if st.Accounting != AccountingCgroups || st.MemoryKills == 0 || !es.Signaled || es.Signal != syscall.SIGKILL {
			t.Fatalf("cgroups bound: accounting %s, kills %d, exit %+v", st.Accounting, st.MemoryKills, es)
		}
		if st.MemoryPeakBytes == 0 || st.MemoryPeakBytes > 64<<20+4<<20 {
			t.Errorf("memory peak %d, want a value at or under the bound", st.MemoryPeakBytes)
		}
		return
	}
	// Under rlimits an address-space cap this small refuses a Go
	// payload its start, which is the bound enforced at the
	// coarseness it has (Limits.MemoryBytes); the allocation-refused
	// shape is pinned by TestMemoryBoundRlimitsRefusesAllocation.
	if st.Accounting != AccountingRlimits || es.Code == 0 {
		t.Fatalf("rlimits bound: accounting %s, exit %+v", st.Accounting, es)
	}
}

// Under rlimits a payload that fits the address-space cap starts, and
// an allocation past it is refused: a shell whose dd asks for a
// 64 MiB buffer under a 32 MiB cap fails after starting.
func TestMemoryBoundRlimitsRefusesAllocation(t *testing.T) {
	if cgroupPlacement(t) {
		t.Skip("cgroup placement available: the rlimits arm is not selected here")
	}
	for _, bin := range []string{"/bin/sh", "/bin/dd"} {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("no %s", bin)
		}
	}
	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:   "/bin/sh",
		Args:   []string{"-c", "echo started; dd if=/dev/zero of=/dev/null bs=64M count=1 2>&1 && echo allocated"},
		Limits: Limits{MemoryBytes: 32 << 20},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if _, err := sb.Wait(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "started") || strings.Contains(got, "allocated") {
		t.Fatalf("rlimits memory bound: %q, want the shell to start and the 64 MiB buffer to be refused", got)
	}
	if st, _ := sb.Stats(); st.Accounting != AccountingRlimits {
		t.Fatalf("accounting %s", st.Accounting)
	}
}

// The process-count bound refuses forks beyond it: the payload's own
// runtime fits under six and its forks are refused — counted by the
// kernel under cgroups, and by the payload alone under rlimits, which
// current kernels count within the sandbox's user namespace.
func TestProcessBound(t *testing.T) {
	requireTree(t)
	cgroups := cgroupPlacement(t)
	if !cgroups {
		// The arm degrades to the rlimits row — unless the counters
		// were demanded of this host.
		testdemand.Degrade(t, "SANDBOX_TEST_REQUIRE_CGROUPS", "cgroup placement is unavailable here")
	}
	var out bytes.Buffer
	sb, err := New(Spec{
		Exec:   "/world",
		Args:   []string{"fork"},
		Root:   worldTree,
		Limits: Limits{MaxProcs: 6},
		Stdout: &out,
		Stderr: &out,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	es, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	st, err := sb.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if cgroups {
		if es.Code != 0 {
			t.Fatalf("payload under the cgroup bound: %+v %s", es, out.String())
		}
		if refused := facts(out.String())["fork-refused"]; refused == "0" || refused == "" {
			t.Fatalf("no fork refused under a bound of 6: %q", out.String())
		}
		if st.Accounting != AccountingCgroups || st.ForksRefused == 0 {
			t.Fatalf("cgroups: accounting %s, forks refused %d", st.Accounting, st.ForksRefused)
		}
		return
	}
	if st.Accounting != AccountingRlimits {
		t.Fatalf("rlimits: accounting %s", st.Accounting)
	}
	if !kernelAtLeast(5, 14) {
		t.Skip("RLIMIT_NPROC is counted per user namespace since kernel 5.14; older kernels count the user's tasks host-wide")
	}
	if es.Code != 0 {
		t.Fatalf("payload under RLIMIT_NPROC=6: %+v %s", es, out.String())
	}
	if refused := facts(out.String())["fork-refused"]; refused == "0" || refused == "" {
		t.Fatalf("no fork refused under RLIMIT_NPROC=6: %q", out.String())
	}
}

// Destroy on a running placed run kills it through the cgroup, reaps
// it, and releases the cgroup; Wait afterwards returns the outcome.
func TestDestroyReleasesCgroup(t *testing.T) {
	requireTree(t)
	requireCgroups(t)
	sb, err := New(Spec{Exec: "/world", Args: []string{"sleep"}, Root: worldTree, Limits: Limits{MaxProcs: 8}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	dir := sb.(*linuxSandbox).bounds.cgroup.Dir
	if err := sb.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cgroup %s survives Destroy: %v", dir, err)
	}
	es, err := sb.Wait()
	if err != nil || !es.Signaled {
		t.Fatalf("Wait after Destroy: %v %+v", err, es)
	}
	if err := sb.Destroy(); err != nil {
		t.Fatalf("second Destroy: %v", err)
	}
}

// A Start refused after the cgroup was created and the child cloned
// — here an entrypoint the init cannot exec — leaves no accounting
// behind, no cgroup, and no tier.
func TestStatsAfterRefusedStart(t *testing.T) {
	requireTree(t)
	requireCgroups(t)
	tree := worldFixture(t)
	if err := os.Chmod(filepath.Join(tree, "world"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := New(Spec{Exec: "/world", Root: tree, Limits: Limits{MemoryBytes: 64 << 20}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "exec /world") {
		t.Fatalf("Start: %v", err)
	}
	if st, err := sb.Stats(); err != nil || st.Accounting != AccountingNone {
		t.Fatalf("Stats after a refused Start = %+v, %v", st, err)
	}
	if sb.Tier() != None {
		t.Fatalf("Tier after a refused Start = %v", sb.Tier())
	}
	if leaked := runCgroups(t); len(leaked) > 0 {
		t.Fatalf("a refused Start left its cgroup behind: %v", leaked)
	}
}

// runCgroups lists this process's run cgroups still standing
// anywhere on the caller's ancestry — every directory Create may
// place in.
func runCgroups(t *testing.T) []string {
	t.Helper()
	h := nslinux.DefaultHierarchy()
	self, err := h.SelfDir()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for dir := self; strings.HasPrefix(dir, h.Root); dir = filepath.Dir(dir) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), fmt.Sprintf("sandbox-%d-", os.Getpid())) {
				out = append(out, filepath.Join(dir, e.Name()))
			}
		}
		if dir == h.Root {
			break
		}
	}
	return out
}

// A cgroup that Wait could not release yet is released by Destroy:
// the cgroup stays owned across the failed release and Destroy after
// Wait retries it.
func TestDestroyRetriesRelease(t *testing.T) {
	requireCgroups(t)
	cg, err := nslinux.DefaultHierarchy().Create(cgroupName("sandbox"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(cg.Dir) })
	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	s := &linuxSandbox{cmd: cmd, waited: true, bounds: bounds{accounting: AccountingCgroups, cgroup: cg}}
	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(cg.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cgroup %s survives Destroy after Wait: %v", cg.Dir, err)
	}
	if s.bounds.cgroup != nil {
		t.Fatal("released cgroup still owned")
	}
}

// A run with no limits stated has no accounting to report; one with
// only rlimit-shaped limits reports rlimits without touching cgroups.
func TestAccountingReported(t *testing.T) {
	requireTree(t)
	sb, err := New(Spec{Exec: "/world", Root: worldTree})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if _, err := sb.Wait(); err != nil {
		t.Fatal(err)
	}
	if st, _ := sb.Stats(); st.Accounting != AccountingNone {
		t.Errorf("no limits: accounting %s", st.Accounting)
	}
	sb, err = New(Spec{Exec: "/world", Root: worldTree, Limits: Limits{CPUSeconds: 60, MaxFiles: 64}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startOrSkip(t, sb)
	if _, err := sb.Wait(); err != nil {
		t.Fatal(err)
	}
	if st, _ := sb.Stats(); st.Accounting != AccountingRlimits {
		t.Errorf("cpu/files limits: accounting %s", st.Accounting)
	}
}

// Cancellation ends a placed run through the cgroup's kill, and the
// cgroup is gone once Wait returns.
func TestCancelKillsPlacedRun(t *testing.T) {
	requireTree(t)
	requireCgroups(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sb, err := New(Spec{Exec: "/world", Args: []string{"sleep"}, Root: worldTree, Limits: Limits{MaxProcs: 8}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	requireUserns(t)
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dir := sb.(*linuxSandbox).bounds.cgroup.Dir
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("placed run has no cgroup: %v", err)
	}
	cancel()
	es, err := sb.Wait()
	if err != nil || !es.Signaled {
		t.Fatalf("Wait after cancel: %v %+v", err, es)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cgroup %s survives Wait: %v", dir, err)
	}
}

// selectBounds maps limits to accounting without a hierarchy where
// none is needed, and to rlimits where the hierarchy affords no
// cgroup, never dropping a stated limit.
func TestSelectBounds(t *testing.T) {
	none := &nslinux.Hierarchy{Root: t.TempDir(), ProcMounts: filepath.Join(t.TempDir(), "mounts"), ProcSelfCgroup: filepath.Join(t.TempDir(), "cg")}
	if err := os.WriteFile(none.ProcMounts, []byte("proc /proc proc rw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := selectBounds(context.Background(), Limits{}, none)
	if err != nil || b.accounting != AccountingNone || len(b.rlimits) != 0 || b.cgroup != nil {
		t.Fatalf("no limits: %+v %v", b, err)
	}
	b, err = selectBounds(context.Background(), Limits{CPUSeconds: 5, MaxFiles: 7}, none)
	if err != nil || b.accounting != AccountingRlimits || len(b.rlimits) != 2 || b.cgroup != nil {
		t.Fatalf("rlimit-shaped limits: %+v %v", b, err)
	}
	b, err = selectBounds(context.Background(), Limits{MemoryBytes: 1 << 20, MaxProcs: 3, CPUSeconds: 5}, none)
	if err != nil || b.accounting != AccountingRlimits || b.cgroup != nil {
		t.Fatalf("no cgroups: %+v %v", b, err)
	}
	var early []int
	for _, rl := range b.rlimits {
		early = append(early, rl.Resource)
	}
	if len(early) != 2 || early[0] != unix.RLIMIT_CPU || early[1] != unix.RLIMIT_AS {
		t.Fatalf("early rlimits = %v, want CPU then AS", early)
	}
	if len(b.late) != 1 || b.late[0].Resource != unix.RLIMIT_NPROC || b.late[0].Cur != 3 {
		t.Fatalf("late rlimits = %+v, want NPROC 3", b.late)
	}
}

// kernelAtLeast reports whether the running kernel is at least
// major.minor.
func kernelAtLeast(major, minor int) bool {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return false
	}
	var rel []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		rel = append(rel, byte(c))
	}
	var gotMajor, gotMinor int
	fmt.Sscanf(string(rel), "%d.%d", &gotMajor, &gotMinor)
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

// The placement probe runs on the caller's clock: a context that has
// already ended refuses Start at once and remembers no answer.
func TestPlacementProbeHonorsContext(t *testing.T) {
	requireTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A hierarchy spelled differently from the default's is a fresh
	// cache entry over the same live kernel interface.
	fresh := &nslinux.Hierarchy{Root: "/sys/fs/cgroup/", ProcMounts: "/proc/self/mounts", ProcSelfCgroup: "/proc/self/cgroup"}
	if _, err := placementSupported(ctx, fresh); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe under a cancelled context: %v", err)
	}
	// Nothing was cached for that hierarchy: a live context probes.
	if _, err := placementSupported(context.Background(), fresh); errors.Is(err, context.Canceled) {
		t.Fatal("the cancelled probe's outcome was remembered")
	}
}

// Cgroup names differ across calls, and residue named after the pid
// alone or the pid and a counter — a predecessor killed at this pid
// with its probe or run cgroup still standing — never shadows the
// next probe or run: Start still places.
func TestCgroupNamesSurviveResidue(t *testing.T) {
	if cgroupName("x") == cgroupName("x") {
		t.Fatal("two cgroup names collide")
	}
	requireTree(t)
	requireCgroups(t)
	h := nslinux.DefaultHierarchy()
	self, err := h.SelfDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		fmt.Sprintf(".placement-%d", os.Getpid()),
		fmt.Sprintf(".placement-%d-1", os.Getpid()),
		fmt.Sprintf("sandbox-%d-1", os.Getpid()),
	} {
		residue := filepath.Join(filepath.Dir(self), name)
		if err := os.Mkdir(residue, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatalf("cannot seed residue beside %s: %v", self, err)
		}
		t.Cleanup(func() { os.Remove(residue) })
	}
	// A hierarchy spelled afresh probes anew, beside the residue.
	fresh := &nslinux.Hierarchy{Root: "/sys/fs/cgroup", ProcMounts: "/proc/mounts", ProcSelfCgroup: "/proc/self/../self/cgroup"}
	ok, err := placementSupported(context.Background(), fresh)
	if err != nil || !ok {
		t.Fatalf("placement beside residue: %v %v", ok, err)
	}
	b, err := selectBounds(context.Background(), Limits{MemoryBytes: 64 << 20}, fresh)
	if err != nil {
		t.Fatalf("run cgroup beside residue: %v", err)
	}
	defer b.cgroup.Delete()
	if b.accounting != AccountingCgroups {
		t.Fatalf("accounting %v, want cgroups", b.accounting)
	}
}

// withHost pins the probed facts for one test, so every row can be
// exercised on one host.
func withHost(t *testing.T, f hostFacts) {
	t.Helper()
	prev := hostOverride
	hostOverride = &f
	t.Cleanup(func() { hostOverride = prev })
}

// Row selection picks the highest row whose facts hold for the
// spec's network intent and names what fails for the rows passed
// over: the network namespace matters only to a spec denying the
// network.
func TestSelectRow(t *testing.T) {
	ns, net, sk := errors.New("namespaces: EPERM"), errors.New("network namespace: EINVAL"), errors.New("seccomp kill-process action: ENOSYS")
	cases := []struct {
		facts   hostFacts
		network bool
		want    row
		below   []string
	}{
		{hostFacts{}, false, strongRow, nil},
		{hostFacts{netns: net}, false, minimalRow, []string{net.Error()}},
		{hostFacts{netns: net}, true, strongRow, nil},
		{hostFacts{namespaces: ns, netns: net}, true, minimalRow, []string{ns.Error()}},
		{hostFacts{seccompKill: sk}, true, minimalRow, []string{sk.Error()}},
		{hostFacts{namespaces: ns, netns: net, seccompKill: sk}, false, minimalRow, []string{ns.Error(), sk.Error()}},
	}
	for _, c := range cases {
		got, below := selectRow(c.facts, c.network)
		if got != c.want || strings.Join(below, "|") != strings.Join(c.below, "|") {
			t.Errorf("selectRow(%+v, %v) = %v %q, want %v %q", c.facts, c.network, got, below, c.want, c.below)
		}
	}
}

// MinTier fails closed before exec: a host reaching only the Minimal
// row refuses a stronger demand at Start, cloning nothing, naming
// what the host lacks; Tier stays None. The same host admits the
// demand it can meet.
func TestMinTierRefusesBeforeExec(t *testing.T) {
	withHost(t, hostFacts{namespaces: errors.New("clone: operation not permitted (forced)")})
	for _, min := range []Isolation{Strong, OS} {
		sb, err := New(Spec{Exec: "/bin/true", Network: true, Limits: Limits{CPUSeconds: 60}, MinTier: min})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		err = sb.Start(context.Background())
		if !errors.Is(err, ErrWeakerThanRequired) {
			t.Fatalf("MinTier %v on a minimal host: %v", min, err)
		}
		var te *TierError
		wrapped := fmt.Errorf("a caller's wrap: %w", err)
		if !errors.As(wrapped, &te) || te.Reached != Minimal || te.Required != min || len(te.Lacking) == 0 || !strings.Contains(te.Lacking[0], "(forced)") {
			t.Fatalf("the refusal as a value: %+v", te)
		}
		if errors.Is(err, ErrUndeliverable) || errors.Is(err, ErrUnsupported) || errors.Unwrap(err) != ErrWeakerThanRequired {
			t.Fatalf("the refusal's class: %v", err)
		}
		for _, want := range []string{"minimal", "(forced)", min.String() + " required"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not name %q", err, want)
			}
		}
		if sb.(*linuxSandbox).cmd != nil || sb.Tier() != None {
			t.Fatalf("a refused Start ran something: tier %v", sb.Tier())
		}
	}
	sb, err := New(Spec{Exec: "/bin/true", Network: true, Limits: Limits{CPUSeconds: 60}, MinTier: Minimal})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start on the admitted row: %v", err)
	}
	if es, err := sb.Wait(); err != nil || es.Code != 0 {
		t.Fatalf("Wait: %+v %v", es, err)
	}
	if sb.Tier() != Minimal {
		t.Fatalf("Tier = %v, want minimal", sb.Tier())
	}
}

// Tier is derived from the row that ran: None before Start, the
// Strong row's tier once it applied.
func TestTierDerived(t *testing.T) {
	requireTree(t)
	sb, err := New(Spec{Exec: "/world", Root: worldTree})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if sb.Tier() != None {
		t.Fatalf("Tier before Start = %v", sb.Tier())
	}
	startOrSkip(t, sb)
	if sb.Tier() != Strong {
		t.Fatalf("Tier after Start = %v", sb.Tier())
	}
	if _, err := sb.Wait(); err != nil {
		t.Fatal(err)
	}
}

// The Minimal row: the caller's own namespaces and world — no pid 1,
// the host's hostname and root, the host's environment — no
// hardening, and the bounds with their accounting reported.
func TestMinimalRow(t *testing.T) {
	requireTree(t)
	withHost(t, hostFacts{namespaces: errors.New("forced")})
	var out bytes.Buffer
	sb, err := New(Spec{Exec: filepath.Join(worldTree, "world"), Network: true, Limits: Limits{CPUSeconds: 60}, Stdout: &out, Stderr: os.Stderr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sb.Tier() != Minimal {
		t.Fatalf("Tier = %v, want minimal", sb.Tier())
	}
	es, err := sb.Wait()
	if err != nil || es.Code != 0 {
		t.Fatalf("Wait: %+v %v\n%s", es, err, out.String())
	}
	f := facts(out.String())
	cwd, _ := os.Getwd()
	cwd, _ = filepath.EvalSymlinks(cwd)
	host, _ := os.ReadFile("/proc/sys/kernel/hostname")
	entries, _ := os.ReadDir("/")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for k, want := range map[string]string{
		"cwd":           cwd,
		"root":          strings.Join(names, ","),
		"nnp":           "0 err=false",
		"proc-hostname": fmt.Sprintf("%q", strings.TrimSpace(string(host))),
	} {
		if f[k] != want {
			t.Errorf("%s = %q, want %q", k, f[k], want)
		}
	}
	if f["pid"] == "1" || f["pid"] == "" {
		t.Errorf("pid = %q: the minimal row has no pid namespace", f["pid"])
	}
	if f["env"] == "0" || f["env"] == "" {
		t.Errorf("env = %q: without a Root the host environment is inherited", f["env"])
	}
	if b, ok := f["bounding"]; !ok || b == "0" {
		t.Errorf("bounding = %q: the minimal row hardens nothing", b)
	}
	st, err := sb.Stats()
	if err != nil || st.Accounting != AccountingRlimits {
		t.Fatalf("Stats = %+v, %v", st, err)
	}
}

// The Minimal row refuses what only a security boundary delivers — a
// Root, a hostname, a denied network, a read-only grant — and a spec
// with no limits, which would leave it nothing to apply; each before
// anything runs. The same intents run on the Strong row.
func TestMinimalRefusesUndeliverable(t *testing.T) {
	requireTree(t)
	withHost(t, hostFacts{namespaces: errors.New("forced")})
	tree := worldFixture(t, "grant-ro")
	world := filepath.Join(tree, "world")
	limits := Limits{CPUSeconds: 60}
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"root", Spec{Exec: "/world", Root: tree, Network: true, Limits: limits}, "cannot restrict the world"},
		{"hostname", Spec{Exec: world, Network: true, Hostname: "h", Limits: limits}, "no hostname"},
		{"network denied", Spec{Exec: world, Limits: limits}, "cannot deny the network"},
		{"read-only grant", Spec{Exec: world, Network: true, Limits: limits, PathGrants: []PathGrant{{Path: filepath.Join(tree, "grant-ro"), Access: ReadOnly}}}, "read-only"},
		{"no limits", Spec{Exec: world, Network: true}, "none were stated"},
	}
	for _, c := range cases {
		sb, err := New(c.spec)
		if err != nil {
			t.Fatalf("%s: New: %v", c.name, err)
		}
		err = sb.Start(context.Background())
		if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrUndeliverable naming %q", c.name, err, c.want)
		}
		if sb.(*linuxSandbox).cmd != nil {
			t.Errorf("%s: something was cloned", c.name)
		}
	}
	withHost(t, hostFacts{})
	requireUserns(t)
	for _, c := range cases[:2] {
		sb, err := New(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); err != nil {
			t.Fatalf("the strong row delivers %s: %v", c.name, err)
		}
		sb.Wait()
	}
}

// Cancellation on the Minimal row kills the run's process group, so a
// child the payload spawned dies with it.
func TestMinimalCancelKillsGroup(t *testing.T) {
	requireTree(t)
	withHost(t, hostFacts{namespaces: errors.New("forced")})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sb, err := New(Spec{Exec: filepath.Join(worldTree, "world"), Args: []string{"spawn"}, Network: true, Limits: Limits{CPUSeconds: 600}, Stdout: w, Stderr: os.Stderr})
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(ctx); err != nil {
		w.Close()
		t.Fatalf("Start: %v", err)
	}
	w.Close()
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "child=") {
		t.Fatalf("payload announced %q, %v", line, err)
	}
	var child int
	fmt.Sscanf(line, "child=%d", &child)
	cancel()
	es, err := sb.Wait()
	if err != nil || !es.Signaled {
		t.Fatalf("Wait after cancel: %+v %v", es, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child))
		if errors.Is(err, os.ErrNotExist) || (err == nil && strings.Contains(string(st), ") Z ")) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the spawned child %d outlived the cancelled run: %q", child, st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The group kill never addresses a group by a reaped leader's pid: a
// leader os.Process knows was waited for is reported gone, and a live
// leader's group is killed whole.
func TestKillRunGuardsReapedLeader(t *testing.T) {
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("no /bin/sleep on this host")
	}
	reaped := exec.Command("/bin/sleep", "60")
	reaped.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := reaped.Start(); err != nil {
		t.Fatal(err)
	}
	reaped.Process.Kill()
	reaped.Wait()
	if err := killRun(minimalRow, bounds{}, reaped.Process); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("a reaped leader: %v, want ErrProcessDone", err)
	}
	// A cgroup kill that failed is the error, even beside a process
	// that is gone: exec ignores a Cancel that says ErrProcessDone.
	err := killRun(minimalRow, bounds{cgroup: &nslinux.Cgroup{Dir: "/nonexistent-cgroup-for-this-test"}}, reaped.Process)
	if err == nil || errors.Is(err, os.ErrProcessDone) || !strings.Contains(err.Error(), "nonexistent-cgroup") {
		t.Fatalf("a failed cgroup kill beside a reaped leader: %v", err)
	}
	live := exec.Command("/bin/sleep", "60")
	live.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	if err := killRun(minimalRow, bounds{}, live.Process); err != nil {
		t.Fatalf("a live leader: %v", err)
	}
	if err := live.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("the group kill did not reach the leader: %v", err)
	}
}

// Start's report of an init that did not reach exec follows the
// status shape: a refused intent is ErrUndeliverable; a row failing
// to apply is reported as that under neither sentinel; a death
// before composing names the contract, or the caller's context.
func TestStartFailureClasses(t *testing.T) {
	ctxErr := context.DeadlineExceeded
	cases := []struct {
		outcome initOutcome
		reason  string
		ctxErr  error
		is      error
		isNot   []error
		text    string
	}{
		{initRefused, "chdir /x: no such file", nil, ErrUndeliverable, []error{ErrWeakerThanRequired}, "chdir /x"},
		{initApplyFailed, "bind /a -> /b: no such file", nil, nil, []error{ErrUndeliverable, ErrWeakerThanRequired}, "the strong row failed to apply on this host: bind /a -> /b"},
		{initDied, "", ctxErr, ctxErr, []error{ErrUndeliverable}, "ended before exec"},
		{initDied, "", nil, nil, []error{ErrUndeliverable}, "must not act under " + envInit},
		{initGarbled, "", nil, nil, []error{ErrUndeliverable}, "unreadable init status"},
	}
	for _, c := range cases {
		err := startFailure(strongRow, c.outcome, c.reason, []byte("junk"), c.ctxErr, errors.New("exit status 127"))
		if c.is != nil && !errors.Is(err, c.is) {
			t.Errorf("%v: %v is not %v", c.outcome, err, c.is)
		}
		for _, not := range c.isNot {
			if errors.Is(err, not) {
				t.Errorf("%v: %v is %v", c.outcome, err, not)
			}
		}
		if !strings.Contains(err.Error(), c.text) {
			t.Errorf("%v: %q lacks %q", c.outcome, err, c.text)
		}
	}
}

// runInitProtocol drives the re-exec protocol as Start does, with a
// config of the test's choosing, and returns the status the init
// wrote.
func runInitProtocol(t *testing.T, cfg initConfig, attr *syscall.SysProcAttr) []byte {
	t.Helper()
	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), envInit+"=1", envInitFD+"=3", envStatusFD+"=4")
	cmd.ExtraFiles = []*os.File{cfgR, statusW}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		t.Fatalf("init: %v", err)
	}
	cfgR.Close()
	statusW.Close()
	if err := json.NewEncoder(cfgW).Encode(&cfg); err != nil {
		t.Fatal(err)
	}
	cfgW.Close()
	status, err := io.ReadAll(statusR)
	statusR.Close()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	return status
}

// The init tells a mechanism that failed to apply — a pivot onto a
// root that is no directory, which the parent never hands it — apart
// from an intent it could not deliver — a bind whose source is gone,
// a working directory it cannot enter — by the status shape it
// writes; and it refuses a row it does not know rather than running
// an unhardened one under that name.
func TestInitReportsApplicationFailure(t *testing.T) {
	requireTree(t)
	requireUserns(t)
	tree, err := filepath.EvalSymlinks(worldFixture(t, "grant-ro"))
	if err != nil {
		t.Fatal(err)
	}
	attr := sysProcAttr(strongRow, false)
	status := runInitProtocol(t, initConfig{Row: Strong.String(), Root: filepath.Join(tree, "etc", "tree-marker"), Cmd: "/world", Env: []string{}}, attr)
	if outcome, reason := classifyStatus(status); outcome != initApplyFailed || !strings.Contains(reason, "pivot") {
		t.Fatalf("a pivot onto a file reported as %v %q (status %q)", outcome, reason, status)
	}
	status = runInitProtocol(t, initConfig{
		Row:   Strong.String(),
		Root:  tree,
		Binds: []bind{{Source: "/nonexistent-source-for-this-test", Target: filepath.Join(tree, "grant-ro")}},
		Cmd:   "/world",
		Env:   []string{},
	}, attr)
	if outcome, reason := classifyStatus(status); outcome != initRefused || !strings.Contains(reason, "bind") {
		t.Fatalf("a vanished bind source reported as %v %q (status %q)", outcome, reason, status)
	}
	status = runInitProtocol(t, initConfig{Row: Strong.String(), Root: tree, WorkDir: "/nonexistent-dir", Cmd: "/world", Env: []string{}}, attr)
	if outcome, reason := classifyStatus(status); outcome != initRefused || !strings.Contains(reason, "chdir") {
		t.Fatalf("an unenterable workdir reported as %v %q (status %q)", outcome, reason, status)
	}
	status = runInitProtocol(t, initConfig{Row: "bogus", Cmd: "/bin/true", Env: []string{}}, sysProcAttr(minimalRow, true))
	if outcome, reason := classifyStatus(status); outcome != initApplyFailed || !strings.Contains(reason, "unknown row") {
		t.Fatalf("an unknown row reported as %v %q (status %q)", outcome, reason, status)
	}
}

// A nil Env without a Root inherits the host's environment minus this
// package's own markers.
func TestHostEnvStripsMarkers(t *testing.T) {
	t.Setenv("_SANDBOX_PROBE_MARKER_TEST", "1")
	t.Setenv("SANDBOX_TEST_KEEP", "1")
	env := hostEnv()
	for _, kv := range env {
		if strings.HasPrefix(kv, "_SANDBOX_") {
			t.Fatalf("marker leaked: %s", kv)
		}
	}
	if !slices.Contains(env, "SANDBOX_TEST_KEEP=1") {
		t.Fatal("the host environment was not inherited")
	}
}

// The memory bound closes swap to the run: the cgroup's
// memory.swap.max reads 0 while it runs; where the kernel keeps no
// such knob yet can hold swap, the run is accounted by rlimits
// instead, never by a cgroup that bounds memory alone.
func TestMemoryBoundClosesSwap(t *testing.T) {
	requireTree(t)
	requireCgroups(t)
	sb, err := New(Spec{Exec: "/world", Args: []string{"sleep"}, Root: worldTree, Limits: Limits{MemoryBytes: 64 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	startOrSkip(t, sb)
	defer sb.Destroy()
	st, err := sb.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Accounting == AccountingRlimits {
		// Only a kernel accounting no swap while able to hold some
		// turns a placeable run onto rlimits.
		probe, err := nslinux.DefaultHierarchy().Create(cgroupName("swapprobe"), []string{"memory"})
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Delete()
		if _, err := os.Stat(filepath.Join(probe.Dir, "memory.swap.max")); !errors.Is(err, os.ErrNotExist) || !nslinux.DefaultHierarchy().SwapPossible() {
			t.Fatalf("accounted by rlimits with a swap knob (%v) or no swap support", err)
		}
		return
	}
	dir := sb.(*linuxSandbox).bounds.cgroup.Dir
	swap, err := os.ReadFile(filepath.Join(dir, "memory.swap.max"))
	if err != nil || strings.TrimSpace(string(swap)) != "0" {
		t.Fatalf("memory.swap.max = %q, %v; want 0", swap, err)
	}
	max, _ := os.ReadFile(filepath.Join(dir, "memory.max"))
	if strings.TrimSpace(string(max)) != "67108864" {
		t.Fatalf("memory.max = %q", max)
	}
}

// A memory limit the kernel cannot extend over swap keeps the cgroup
// where the kernel can hold no swap and falls to rlimits where it
// can; any other failure of the limit is a failure.
func TestSwapUnbounded(t *testing.T) {
	possible := func() bool { return true }
	impossible := func() bool { return false }
	unaccounted := fmt.Errorf("%w: enoent", nslinux.ErrSwapUnaccounted)
	cases := []struct {
		name string
		err  error
		swap func() bool
		want bool
		fail string
	}{
		{"bounded", nil, possible, false, ""},
		{"no knob, swap possible", unaccounted, possible, true, ""},
		{"no knob, no swap support", unaccounted, impossible, false, ""},
		{"other failure", errors.New("EACCES"), impossible, false, "EACCES"},
	}
	for _, c := range cases {
		got, err := swapUnbounded(c.err, c.swap)
		if c.fail != "" {
			if err == nil || !strings.Contains(err.Error(), c.fail) {
				t.Errorf("%s: %v %v", c.name, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %v %v, want %v", c.name, got, err, c.want)
		}
	}
}

// Where the kernel accounts no swap, a placeable run keeps its cgroup
// on a kernel without swap support and falls to rlimits — the cgroup
// released — on one that can hold swap.
func TestSelectBoundsWithoutSwapAccounting(t *testing.T) {
	requireCgroups(t)
	prev := setMemoryMax
	setMemoryMax = func(c *nslinux.Cgroup, bytes uint64) error {
		if err := prev(c, bytes); err != nil {
			return err
		}
		return fmt.Errorf("%w: forced", nslinux.ErrSwapUnaccounted)
	}
	t.Cleanup(func() { setMemoryMax = prev })
	swaps := func(present bool) *nslinux.Hierarchy {
		p := filepath.Join(t.TempDir(), "swaps")
		if present {
			if err := os.WriteFile(p, []byte("Filename\tType\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		h := nslinux.DefaultHierarchy()
		h.ProcSwaps = p
		return h
	}
	b, err := selectBounds(context.Background(), Limits{MemoryBytes: 64 << 20}, swaps(true))
	if err != nil || b.accounting != AccountingRlimits || b.cgroup != nil {
		t.Fatalf("swap possible: %+v %v, want rlimits and no cgroup", b, err)
	}
	if leaked := runCgroups(t); len(leaked) > 0 {
		t.Fatalf("the cgroup outlived the fallback: %v", leaked)
	}
	b, err = selectBounds(context.Background(), Limits{MemoryBytes: 64 << 20}, swaps(false))
	if err != nil || b.accounting != AccountingCgroups || b.cgroup == nil {
		t.Fatalf("no swap support: %+v %v, want cgroups", b, err)
	}
	b.cgroup.Delete()
	// A cgroup the fallback cannot release — a member holds it — is
	// reported, never left behind in silence.
	var held *exec.Cmd
	setMemoryMax = func(c *nslinux.Cgroup, bytes uint64) error {
		held = exec.Command("/bin/sleep", "60")
		held.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := held.Start(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(c.Dir, "cgroup.procs"), []byte(strconv.Itoa(held.Process.Pid)), 0o644); err != nil {
			t.Fatal(err)
		}
		return fmt.Errorf("%w: forced", nslinux.ErrSwapUnaccounted)
	}
	_, err = selectBounds(context.Background(), Limits{MemoryBytes: 64 << 20}, swaps(true))
	held.Process.Kill()
	held.Wait()
	for _, dir := range runCgroups(t) {
		os.Remove(dir)
	}
	if err == nil || !strings.Contains(err.Error(), "releasing the cgroup left unused") {
		t.Fatalf("a held cgroup on the fallback: %v", err)
	}
}

// A MinTier naming no tier is refused at construction, before any
// probe: the tiers are None through Strong.
func TestNewRefusesUnknownMinTier(t *testing.T) {
	for _, min := range []Isolation{Isolation(-1), Strong + 1, Isolation(42)} {
		if _, err := New(Spec{Exec: "/bin/true", Network: true, Limits: Limits{CPUSeconds: 60}, MinTier: min}); err == nil || !strings.Contains(err.Error(), "names no tier") {
			t.Errorf("MinTier %d: %v", min, err)
		}
	}
}
