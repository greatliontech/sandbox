//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/greatliontech/sandbox/internal/testdemand"
	"golang.org/x/sys/unix"
)

// childEnv selects the payload's behaviour when this test binary is
// run as the payload: it reports facts, one "key=value" line each,
// or holds a shape the bounds and kill tests need.
const childEnv = "SANDBOX_TEST_DARWIN_CHILD"

func TestMain(m *testing.M) {
	mode := os.Getenv(childEnv)
	if len(os.Args) > 1 && os.Args[1] == "world" {
		mode = "world"
	}
	switch mode {
	case "":
	case "hello":
		fmt.Println("hello=yes")
		os.Exit(0)
	case "exit7":
		os.Exit(7)
	case "net":
		c, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
		if c != nil {
			c.Close()
		}
		fmt.Printf("net=%v\n", err)
		os.Exit(0)
	case "write":
		err := os.WriteFile(os.Getenv("SANDBOX_TEST_WRITE"), []byte("x"), 0o644)
		fmt.Printf("write=%v\n", err)
		os.Exit(0)
	case "unix":
		// Listen and dial a unix socket at the named path.
		p := os.Getenv("SANDBOX_TEST_SOCK")
		l, err := net.Listen("unix", p)
		if err != nil {
			fmt.Printf("unix=listen: %v\n", err)
			os.Exit(0)
		}
		go func() {
			c, err := l.Accept()
			if err == nil {
				c.Close()
			}
		}()
		c, err := net.Dial("unix", p)
		if c != nil {
			c.Close()
		}
		l.Close()
		fmt.Printf("unix=%v\n", err)
		os.Exit(0)
	case "threads":
		// Park three hundred threads, then wait: under a smaller
		// process bound the watchdog kills.
		var n int
		fmt.Sscan(os.Getenv("SANDBOX_TEST_THREADS"), &n)
		block := make(chan struct{})
		for i := 0; i < n; i++ {
			go func() {
				runtime.LockOSThread()
				<-block
			}()
		}
		time.Sleep(200 * time.Millisecond)
		fmt.Println("threads=parked")
		os.Stdout.Sync()
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "rlimits":
		for _, r := range []struct {
			name string
			res  int
		}{{"cpu", unix.RLIMIT_CPU}, {"nofile", unix.RLIMIT_NOFILE}} {
			var l unix.Rlimit
			if err := unix.Getrlimit(r.res, &l); err != nil {
				fmt.Printf("%s=err:%v\n", r.name, err)
				continue
			}
			fmt.Printf("%s=%d\n", r.name, l.Cur)
		}
		fmt.Printf("cwd=%s\n", must(os.Getwd()))
		os.Exit(0)
	case "hog":
		// Announce, then hold 256 MiB: under a smaller memory bound
		// the watchdog kills after the announcement.
		fmt.Println("hog=start")
		os.Stdout.Sync()
		var chunks [][]byte
		for i := 0; i < 256; i++ {
			c := make([]byte, 1<<20)
			for j := 0; j < len(c); j += 4096 {
				c[j] = byte(j)
			}
			chunks = append(chunks, c)
		}
		fmt.Printf("hogged=%d\n", len(chunks))
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "spin":
		// Burn CPU with the kernel's signal ignored: only the watchdog
		// can end this under a CPU bound.
		signal.Ignore(syscall.SIGXCPU)
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
		}
		fmt.Println("spun=yes")
		os.Exit(0)
	case "spawn":
		// Start a long sleeper, name it, and sleep alongside it: the
		// cancellation test checks the kill reaches both.
		cmd := exec.Command(must(os.Executable()))
		cmd.Env = append(os.Environ(), childEnv+"=sleep")
		if err := cmd.Start(); err != nil {
			fmt.Printf("spawn=err:%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("child=%d\n", cmd.Process.Pid)
		os.Stdout.Sync()
		time.Sleep(5 * time.Minute)
		os.Exit(0)
	case "spawn-exit":
		// Start a long sleeper holding this output, name it, and exit:
		// the run's end must end the sleeper and release the output.
		cmd := exec.Command(must(os.Executable()))
		cmd.Env = append(os.Environ(), childEnv+"=sleep")
		cmd.Stdout = os.Stdout
		if err := cmd.Start(); err != nil {
			fmt.Printf("spawn=err:%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("child=%d\n", cmd.Process.Pid)
		os.Exit(0)
	case "sleep":
		time.Sleep(5 * time.Minute)
		os.Exit(0)
	case "world":
		// Report what the world lets this process see and touch, one
		// fact a line: the arguments name the tree, a read-only grant,
		// a read-write grant, the rendezvous directory, a path outside
		// the tree and a unix socket outside the tree a listener holds
		// (each may be empty).
		tree, ro, rw, rt, outside, outSock := os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7]
		cwd, _ := os.Getwd()
		fmt.Printf("cwd=%s\n", cwd)
		fmt.Printf("env=%d\n", len(os.Environ()))
		_, err := os.ReadFile(filepath.Join(tree, "etc", "tree-marker"))
		fmt.Printf("readtree=%v\n", err)
		_, err = os.ReadFile(outside)
		fmt.Printf("readoutside=%v\n", err)
		_, err = os.ReadFile("/System/Volumes/Data" + outside)
		fmt.Printf("readalias=%v\n", err)
		_, err = net.LookupHost("one.one.one.one")
		fmt.Printf("lookup=%v\n", err)
		fmt.Printf("writetree=%v\n", os.WriteFile(filepath.Join(tree, "etc", "w"), []byte("x"), 0o644))
		if ro != "" {
			fmt.Printf("writero=%v\n", os.WriteFile(filepath.Join(ro, "w"), []byte("x"), 0o644))
			_, err = os.ReadDir(ro)
			fmt.Printf("readro=%v\n", err)
		}
		if rw != "" {
			fmt.Printf("writerw=%v\n", os.WriteFile(filepath.Join(rw, "w"), []byte("x"), 0o644))
		}
		if rt != "" {
			l, err := net.Listen("unix", filepath.Join(rt, "s"))
			if err == nil {
				l.Close()
			}
			fmt.Printf("unixrt=%v\n", err)
			l, err = net.Listen("unix", filepath.Join(filepath.Dir(outside), "s"))
			if err == nil {
				l.Close()
			}
			fmt.Printf("unixout=%v\n", err)
		}
		if outSock != "" {
			c, err := net.Dial("unix", outSock)
			if c != nil {
				c.Close()
			}
			fmt.Printf("dialout=%v\n", err)
		}
		fmt.Printf("cores=%v\n", os.WriteFile("/cores/sandbox-test", []byte("x"), 0o644))
		c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
		if c != nil {
			c.Close()
		}
		fmt.Printf("net=%v\n", err)
		out, err := exec.Command("/bin/ls", "/").CombinedOutput()
		fmt.Printf("execout=%v\n", err)
		_ = out
		sib := exec.Command(filepath.Join(tree, "sibling"))
		sib.Env = []string{childEnv + "=hello"}
		sout, err := sib.Output()
		fmt.Printf("sibling=%v:%s\n", err, strings.TrimSpace(string(sout)))
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown child mode %q\n", mode)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// requireSeatbelt skips an OS-row arm where the host has no
// sandbox-exec to apply a profile — unless SANDBOX_TEST_REQUIRE_SEATBELT
// demands the row, in which case a host that was meant to deliver it
// fails instead of skipping.
func requireSeatbelt(t testing.TB) {
	t.Helper()
	f, err := hostFactsFor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unavailable := ""
	if f.seatbelt != nil {
		unavailable = "seatbelt is unavailable here: " + f.seatbelt.Error()
	}
	testdemand.Live(t, "SANDBOX_TEST_REQUIRE_SEATBELT", unavailable)
}

// overrideMinimal makes every selection reach the Minimal row, the
// probe's answer set aside: the shared tests' name for it.
func overrideMinimal(t *testing.T) { withoutSeatbelt(t) }

// withoutSeatbelt makes every selection in the test reach the Minimal
// row, the probe's answer set aside.
func withoutSeatbelt(t *testing.T) {
	t.Helper()
	hostOverride = &hostFacts{seatbelt: errors.New("sandbox-exec set aside for the test")}
	t.Cleanup(func() { hostOverride = nil })
}

// payload is a spec running this binary as the payload in the named
// mode, its output captured.
func payload(mode string, env ...string) (Spec, *output) {
	out := &output{}
	return Spec{
		Exec:   must(os.Executable()),
		Env:    append([]string{childEnv + "=" + mode}, env...),
		Stdout: out,
		Stderr: os.Stderr,
	}, out
}

func TestSelectRow(t *testing.T) {
	if r, below := selectRow(hostFacts{}); r.tier != OS || len(below) != 0 {
		t.Fatalf("seatbelt present: %v %v", r.tier, below)
	}
	if r, below := selectRow(hostFacts{seatbelt: errors.New("no sandbox-exec")}); r.tier != Minimal || len(below) != 1 || below[0] != "no sandbox-exec" {
		t.Fatalf("seatbelt absent: %v %v", r.tier, below)
	}
}

// TestReachIsStartsSelection pins Reach to the selection Start makes:
// the OS row where this host applies a profile, demanded on the
// macOS row.
func TestReachIsStartsSelection(t *testing.T) {
	requireSeatbelt(t)
	tier, below, err := Reach(context.Background(), Spec{Exec: "/x"})
	if err != nil || tier != OS || len(below) != 0 {
		t.Fatalf("Reach = %v %v %v, want OS", tier, below, err)
	}
	withoutSeatbelt(t)
	tier, below, err = Reach(context.Background(), Spec{Exec: "/x"})
	if err != nil || tier != Minimal || len(below) != 1 {
		t.Fatalf("Reach without seatbelt = %v %v %v, want Minimal with one lack", tier, below, err)
	}
}

func TestMinimalRow(t *testing.T) {
	withoutSeatbelt(t)
	spec, out := payload("hello")
	spec.Network = true
	spec.Limits = Limits{MaxFiles: 256}
	sb, st := run(t, spec)
	if st.Code != 0 || facts(out.String())["hello"] != "yes" {
		t.Fatalf("exit %+v, output %q", st, out.String())
	}
	if sb.Tier() != Minimal {
		t.Fatalf("tier %v, want Minimal", sb.Tier())
	}
	stats, err := sb.Stats()
	if err != nil || stats.Accounting != AccountingRlimits {
		t.Fatalf("stats %+v %v, want rlimits", stats, err)
	}
	spec, _ = payload("exit7")
	spec.Network = true
	spec.Limits = Limits{MaxFiles: 256}
	if _, st := run(t, spec); st.Code != 7 {
		t.Fatalf("exit %+v, want 7", st)
	}
}

func TestMinimalRefusesUndeliverable(t *testing.T) {
	withoutSeatbelt(t)
	base := func() Spec {
		s, _ := payload("hello")
		s.Network = true
		s.Limits = Limits{MaxFiles: 256}
		return s
	}
	for name, mutate := range map[string]func(*Spec){
		"a root":           func(s *Spec) { s.Root = rootTree(t); s.Exec = "/payload" },
		"a hostname":       func(s *Spec) { s.Hostname = "box" },
		"a denied network": func(s *Spec) { s.Network = false },
		"a read-only grant": func(s *Spec) {
			s.PathGrants = []PathGrant{{Path: t.TempDir(), Access: ReadOnly}}
		},
		"no limits": func(s *Spec) { s.Limits = Limits{} },
	} {
		spec := base()
		mutate(&spec)
		sb, err := New(spec)
		if err != nil {
			t.Fatal(err)
		}
		err = sb.Start(context.Background())
		if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "the minimal row") {
			t.Errorf("%s on the Minimal row: %v, want the row's own refusal", name, err)
			sb.Destroy()
		}
	}
}

func TestMinTierRefusesBeforeExec(t *testing.T) {
	withoutSeatbelt(t)
	spec, out := payload("hello")
	spec.Network = true
	spec.Limits = Limits{MaxFiles: 256}
	spec.MinTier = OS
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	err = sb.Start(context.Background())
	var te *TierError
	if !errors.As(err, &te) || te.Reached != Minimal || te.Required != OS || len(te.Lacking) != 1 {
		t.Fatalf("Start = %v, want a tier error naming Minimal, OS and one lack", err)
	}
	if out.Len() != 0 || sb.Tier() != None {
		t.Fatalf("something ran under a refused tier: %q, tier %v", out.String(), sb.Tier())
	}
}

func TestNewRefusesUnknownMinTier(t *testing.T) {
	if _, err := New(Spec{Exec: "/x", MinTier: Strong + 1}); err == nil {
		t.Fatal("New accepted a MinTier naming no tier")
	}
}

// TestOSRowNetwork pins the OS row's network denial and grant: the
// profile denies the network unless the spec grants it.
func TestOSRowNetwork(t *testing.T) {
	requireSeatbelt(t)
	spec, out := payload("net")
	sb, st := run(t, spec)
	if st.Code != 0 || !strings.Contains(facts(out.String())["net"], "operation not permitted") {
		t.Fatalf("a denied network: exit %+v, net=%q", st, facts(out.String())["net"])
	}
	if sb.Tier() != OS {
		t.Fatalf("tier %v, want OS", sb.Tier())
	}
	spec, out = payload("net")
	spec.Network = true
	if _, st := run(t, spec); st.Code != 0 || strings.Contains(facts(out.String())["net"], "operation not permitted") {
		t.Fatalf("a granted network: exit %+v, net=%q", st, facts(out.String())["net"])
	}
}

// TestRlimitsApplied pins the kernel's bounds reaching the payload,
// the working directory entered, and the accounting reported: the
// open-files limit alone is the kernel's, a CPU bound the
// watchdog's.
func TestRlimitsApplied(t *testing.T) {
	wd := must(filepath.EvalSymlinks(t.TempDir()))
	spec, out := payload("rlimits")
	spec.Limits = Limits{MaxFiles: 300}
	spec.WorkDir = wd
	sb, st := run(t, spec)
	f := facts(out.String())
	if st.Code != 0 || f["nofile"] != "300" || f["cwd"] != wd {
		t.Fatalf("exit %+v, facts %v", st, f)
	}
	stats, err := sb.Stats()
	if err != nil || stats.Accounting != AccountingRlimits {
		t.Fatalf("stats %+v %v, want rlimits", stats, err)
	}
	spec, out = payload("rlimits")
	spec.Limits = Limits{CPUSeconds: 100, MaxFiles: 300}
	sb, st = run(t, spec)
	f = facts(out.String())
	if st.Code != 0 || f["cpu"] != "100" || f["nofile"] != "300" {
		t.Fatalf("exit %+v, facts %v", st, f)
	}
	stats, err = sb.Stats()
	if err != nil || stats.Accounting != AccountingWatchdog {
		t.Fatalf("stats %+v %v, want the watchdog", stats, err)
	}
}

// TestProcessBoundKillsThreads pins the process bound as the
// watchdog holds it: the run's processes and threads summed.
func TestProcessBoundKillsThreads(t *testing.T) {
	spec, out := payload("threads", "SANDBOX_TEST_THREADS=300")
	spec.Limits = Limits{MaxProcs: 100}
	sb, st := run(t, spec)
	if !st.Signaled || st.Signal != syscall.SIGKILL {
		t.Fatalf("exit %+v, output %q; want a kill", st, out.String())
	}
	if stats, err := sb.Stats(); err != nil || stats.ProcessKills != 1 || stats.MemoryKills != 0 || stats.CPUKills != 0 {
		t.Fatalf("stats %+v %v, want the watchdog's kill by the process bound", stats, err)
	}
	spec, out = payload("threads", "SANDBOX_TEST_THREADS=20")
	spec.Limits = Limits{MaxProcs: 100}
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for facts(out.String())["threads"] == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if facts(out.String())["threads"] != "parked" {
		t.Fatalf("under the bound the payload never parked: %q", out.String())
	}
	// Alive under the bound right up to the cancellation.
	time.Sleep(100 * time.Millisecond)
	if err := sb.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the payload under the bound died: %v", err)
	}
	cancel()
	if st, err := sb.Wait(); err != nil || !st.Signaled {
		t.Fatalf("Wait after cancel: %+v %v", st, err)
	}
}

// TestWatchdogReadsPlatformBinaries pins the watchdog's readings of
// a payload that is the platform's own binary, not this one: the
// kernel shows it to the sandbox, so the run ends by its own exit,
// in bounds and without a watchdog error.
func TestWatchdogReadsPlatformBinaries(t *testing.T) {
	out := &output{}
	sb, st := run(t, Spec{
		Exec:   "/bin/sh",
		Args:   []string{"-c", "/bin/sleep 0.5; echo shell=done"},
		Limits: Limits{MemoryBytes: 256 << 20, CPUSeconds: 10},
		Stdout: out,
		Stderr: os.Stderr,
	})
	if st.Code != 0 || st.Signaled || facts(out.String())["shell"] != "done" {
		t.Fatalf("exit %+v, output %q; want the shell done", st, out.String())
	}
	stats, err := sb.Stats()
	if err != nil || stats.Accounting != AccountingWatchdog || stats.MemoryKills != 0 || stats.MemoryPeakBytes == 0 {
		t.Fatalf("stats %+v %v, want the watchdog's reading of the shell", stats, err)
	}
}

// TestRunEndKillsRemnants pins the run's end as a kill trigger: a
// descendant the payload leaves behind, holding the payload's
// output, neither outlives the payload nor holds Wait open.
func TestRunEndKillsRemnants(t *testing.T) {
	spec, out := payload("spawn-exit")
	spec.Limits = Limits{MaxFiles: 256}
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	st, err := sb.Wait()
	if err != nil || st.Code != 0 {
		t.Fatalf("Wait: %+v %v", st, err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Wait held open by the remnant for %v", elapsed)
	}
	child, err := strconv.Atoi(facts(out.String())["child"])
	if err != nil {
		t.Fatalf("the payload named no child: %q", out.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(child, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the remnant %d outlived the run", child)
}

// TestOSRowUnixSockets pins what a denied network leaves open: a
// unix socket reached by path.
func TestOSRowUnixSockets(t *testing.T) {
	requireSeatbelt(t)
	dir := must(filepath.EvalSymlinks(t.TempDir()))
	spec, out := payload("unix", "SANDBOX_TEST_SOCK="+filepath.Join(dir, "s"))
	if _, st := run(t, spec); st.Code != 0 || facts(out.String())["unix"] != "<nil>" {
		t.Fatalf("a unix socket under a denied network: exit %+v, unix=%q", st, facts(out.String())["unix"])
	}
}

// TestOSRowRefusesReadOnlyGrantWithoutRoot pins the OS row's refusal:
// without a Root its profile allows the whole world, where no rule
// keeps a grant read-only past a renamed ancestor.
func TestOSRowRefusesReadOnlyGrantWithoutRoot(t *testing.T) {
	requireSeatbelt(t)
	spec, _ := payload("hello")
	spec.PathGrants = []PathGrant{{Path: t.TempDir(), Access: ReadOnly}}
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) {
		t.Fatalf("Start = %v, want ErrUndeliverable", err)
	}
}

// TestApplierFailureIsStarts pins the staged init: the applier
// refusing the profile is the row failing to apply, reported by
// Start, never the payload's exit.
func TestApplierFailureIsStarts(t *testing.T) {
	requireSeatbelt(t)
	profileOverride = "(version 1)(this is no profile"
	t.Cleanup(func() { profileOverride = "" })
	spec, out := payload("hello")
	spec.Stderr = io.Discard
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	err = sb.Start(context.Background())
	if err == nil || errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "failed to apply") {
		t.Fatalf("Start = %v, want the row failing to apply", err)
	}
	if out.Len() != 0 || sb.Tier() != None {
		t.Fatalf("something ran under a refused profile: %q, tier %v", out.String(), sb.Tier())
	}
}

// TestMemoryWatchdogKillsHog pins the memory bound: a payload holding
// four times the bound is killed by the watchdog, after its
// announcement, and the account says so.
func TestMemoryWatchdogKillsHog(t *testing.T) {
	spec, out := payload("hog")
	spec.Limits = Limits{MemoryBytes: 64 << 20}
	sb, st := run(t, spec)
	if !st.Signaled || st.Signal != syscall.SIGKILL || st.Code != 128+int(syscall.SIGKILL) {
		t.Fatalf("exit %+v, output %q; want a kill, its code 128 plus the signal", st, out.String())
	}
	f := facts(out.String())
	if f["hog"] != "start" || f["hogged"] != "" {
		t.Fatalf("the hog's announcement: %v", f)
	}
	stats, err := sb.Stats()
	if err != nil || stats.Accounting != AccountingWatchdog || stats.MemoryKills != 1 || stats.CPUKills != 0 || stats.ProcessKills != 0 || stats.MemoryPeakBytes <= 64<<20 {
		t.Fatalf("stats %+v %v, want the watchdog's kill by the memory bound past it", stats, err)
	}
}

// TestCPUWatchdogKillsSpinner pins the CPU bound behind the kernel's
// signal: a payload ignoring SIGXCPU is killed by the watchdog.
func TestCPUWatchdogKillsSpinner(t *testing.T) {
	spec, out := payload("spin")
	spec.Limits = Limits{CPUSeconds: 1}
	start := time.Now()
	sb, st := run(t, spec)
	if !st.Signaled || st.Signal != syscall.SIGKILL || facts(out.String())["spun"] == "yes" {
		t.Fatalf("exit %+v after %v, output %q; want a kill", st, time.Since(start), out.String())
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("the kill took %v", elapsed)
	}
	if stats, err := sb.Stats(); err != nil || stats.CPUKills != 1 || stats.MemoryKills != 0 || stats.ProcessKills != 0 {
		t.Fatalf("stats %+v %v, want the watchdog's kill by the CPU bound", stats, err)
	}
}

// TestCancelKillsGroup pins the kill tie: cancellation kills the
// run's process group, a forked descendant included.
func TestCancelKillsGroup(t *testing.T) {
	spec, out := payload("spawn")
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for facts(out.String())["child"] == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	child, err := strconv.Atoi(facts(out.String())["child"])
	if err != nil {
		t.Fatalf("the payload named no child: %q", out.String())
	}
	cancel()
	st, err := sb.Wait()
	if err != nil || !st.Signaled {
		t.Fatalf("Wait after cancel: %+v %v", st, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(child, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the descendant %d outlived the cancellation", child)
}

// TestStartRefusals pins what Start refuses before anything runs.
func TestStartRefusals(t *testing.T) {
	cases := map[string]func(*Spec){
		"a missing entrypoint":  func(s *Spec) { s.Exec = filepath.Join(t.TempDir(), "nope") },
		"a relative entrypoint": func(s *Spec) { s.Exec = "relative" },
		"a hostname":            func(s *Spec) { s.Hostname = "box" },
		"an absent working directory": func(s *Spec) {
			s.WorkDir = filepath.Join(t.TempDir(), "absent")
		},
	}
	for name, mutate := range cases {
		spec, out := payload("hello")
		mutate(&spec)
		sb, err := New(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) {
			t.Errorf("%s: %v, want ErrUndeliverable", name, err)
			sb.Destroy()
		}
		if out.Len() != 0 {
			t.Errorf("%s: something ran: %q", name, out.String())
		}
	}
}

// rootTree builds a tree with this binary as the entrypoint and as a
// sibling, a marker file, and directories for a read-only grant, a
// read-write grant and the rendezvous directory; the tree's path is
// returned as the host spells it.
func rootTree(t *testing.T) string {
	t.Helper()
	tree := must(filepath.EvalSymlinks(t.TempDir()))
	exe := must(os.Executable())
	b := must(os.ReadFile(exe))
	for _, name := range []string{"payload", "sibling"} {
		if err := os.WriteFile(filepath.Join(tree, name), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"etc", "grant-ro", "grant-rw", "run"} {
		if err := os.Mkdir(filepath.Join(tree, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tree, "etc", "tree-marker"), []byte("tree"), 0o644); err != nil {
		t.Fatal(err)
	}
	return tree
}

// TestRootWorld pins the OS row's world under a Root on this platform
// (docs/specs/sandbox.md, "Root is world-restriction"): the tree
// readable and executable at its host path and nothing else of the
// host but the platform's substrate; the tree never written; a
// read-only grant read, a read-write grant written; unix sockets
// within the rendezvous directory alone; the network denied; a
// sibling of the tree executed by the entrypoint, the host's
// binaries not; the environment exactly the stated; the working
// directory the tree's root.
func TestRootWorld(t *testing.T) {
	requireSeatbelt(t)
	tree := rootTree(t)
	outsideDir := must(filepath.EvalSymlinks(t.TempDir()))
	outside := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(outside, []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The grants and the rendezvous directory exist on the host at
	// their own paths and in the tree at the same paths, as the tree
	// resolution requires.
	hostRO, hostRW, hostRT := must(filepath.EvalSymlinks(t.TempDir())), must(filepath.EvalSymlinks(t.TempDir())), must(filepath.EvalSymlinks(t.TempDir()))
	for _, d := range []string{hostRO, hostRW, hostRT} {
		if err := os.MkdirAll(filepath.Join(tree, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A listener outside the tree, which the payload must not reach.
	outSock := filepath.Join(outsideDir, "out.sock")
	l, err := net.Listen("unix", outSock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	out := &output{}
	spec := Spec{
		Exec:       "/payload",
		Args:       []string{"world", tree, hostRO, hostRW, hostRT, outside, outSock},
		Env:        []string{"ONE=1", "TWO=2"},
		Root:       tree,
		PathGrants: []PathGrant{{Path: hostRO, Access: ReadOnly}, {Path: hostRW, Access: ReadWrite}},
		RuntimeDir: hostRT,
		Stdout:     out,
		Stderr:     os.Stderr,
	}
	sb, st := run(t, spec)
	if st.Code != 0 || sb.Tier() != OS {
		t.Fatalf("exit %+v, tier %v, output %q", st, sb.Tier(), out.String())
	}
	f := facts(out.String())
	denied := func(key string) {
		t.Helper()
		if !strings.Contains(f[key], "operation not permitted") {
			t.Errorf("%s = %q, want denied", key, f[key])
		}
	}
	allowed := func(key string) {
		t.Helper()
		if f[key] != "<nil>" {
			t.Errorf("%s = %q, want allowed", key, f[key])
		}
	}
	if f["cwd"] != tree {
		t.Errorf("cwd = %q, want the tree %q", f["cwd"], tree)
	}
	if f["env"] != "2" {
		t.Errorf("env = %q entries, want the two stated", f["env"])
	}
	allowed("readtree")
	denied("readoutside")
	denied("readalias")
	denied("writetree")
	allowed("readro")
	denied("writero")
	allowed("writerw")
	allowed("unixrt")
	denied("unixout")
	denied("dialout")
	denied("net")
	if f["lookup"] == "<nil>" {
		t.Errorf("lookup = %q under a denied network, want no name resolution", f["lookup"])
	}
	denied("execout")
	// The profile's refusal where the host would let the write
	// through; the host's own where /cores is not the user's to
	// write, which hides the profile's but refuses all the same.
	if !strings.Contains(f["cores"], "operation not permitted") && !strings.Contains(f["cores"], "permission denied") {
		t.Errorf("cores = %q, want a refusal", f["cores"])
	}
	if !strings.HasPrefix(f["sibling"], "<nil>:hello=yes") {
		t.Errorf("sibling = %q, want the sibling executed", f["sibling"])
	}
	if _, err := os.Stat(filepath.Join(tree, "etc", "w")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the tree was written: %v", err)
	}
	// The network granted: by address, a unix socket elsewhere still
	// not the payload's; an unstated environment empty.
	out = &output{}
	spec.Network = true
	spec.Env = nil
	spec.Stdout = out
	if _, st := run(t, spec); st.Code != 0 {
		t.Fatalf("with the network: exit %+v, output %q", st, out.String())
	}
	f = facts(out.String())
	if strings.Contains(f["net"], "operation not permitted") {
		t.Errorf("net = %q under a granted network", f["net"])
	}
	if f["lookup"] != "<nil>" {
		t.Errorf("lookup = %q under a granted network, want name resolution", f["lookup"])
	}
	denied("dialout")
	if f["env"] != "0" {
		t.Errorf("env = %q entries unstated, want none", f["env"])
	}
}

// TestRootOverlappingSpellingsRefused pins the overlap judged by
// identity on this platform: two grants naming one directory by two
// spellings (a case variant's), one read-only and one read-write,
// are refused as overlapping.
func TestRootOverlappingSpellingsRefused(t *testing.T) {
	requireSeatbelt(t)
	tree := rootTree(t)
	host := must(filepath.EvalSymlinks(t.TempDir()))
	variant := strings.ToUpper(host)
	if _, err := os.Stat(variant); err != nil {
		t.Skipf("a case variant is no alias on this volume: %v", err)
	}
	for _, p := range []string{host, variant} {
		if err := os.MkdirAll(filepath.Join(tree, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sb, err := New(Spec{Exec: "/payload", Env: []string{childEnv + "=hello"}, Root: tree, PathGrants: []PathGrant{{Path: host, Access: ReadOnly}, {Path: variant, Access: ReadWrite}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("two spellings of one grant: %v, want refused as overlapping", err)
	}
}

// TestRootAliasedGrantsRefused pins the containment judged by
// identity on this platform: a grant naming the tree's parent
// through a firmlink or a case variant is refused as holding the
// tree, and so is a grant of the data volume's mount point or of a
// directory above it, under which the tree is reached with no
// firmlink crossed.
func TestRootAliasedGrantsRefused(t *testing.T) {
	requireSeatbelt(t)
	parent := must(filepath.EvalSymlinks(t.TempDir()))
	tree := filepath.Join(parent, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := must(os.Executable())
	if err := os.WriteFile(filepath.Join(tree, "payload"), must(os.ReadFile(exe)), 0o755); err != nil {
		t.Fatal(err)
	}
	aliases := map[string]string{
		"a case variant":                    strings.ToUpper(parent),
		"a firmlink":                        "/System/Volumes/Data" + parent,
		"the data volume":                   "/System/Volumes/Data",
		"a directory above the data volume": "/System/Volumes",
	}
	for name, alias := range aliases {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(alias); err != nil {
				testdemand.Live(t, "SANDBOX_TEST_REQUIRE_SEATBELT", fmt.Sprintf("%s %s not on this host: %v", name, alias, err))
			}
			if err := os.MkdirAll(filepath.Join(tree, alias), 0o755); err != nil {
				t.Fatal(err)
			}
			sb, err := New(Spec{Exec: "/payload", Env: []string{childEnv + "=hello"}, Root: tree, PathGrants: []PathGrant{{Path: alias, Access: ReadWrite}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "holds the tree") {
				t.Errorf("%s %s granted over the tree's parent: %v, want refused as holding the tree", name, alias, err)
				sb.Destroy()
			}
		})
	}
}

// TestAutomountGrantRefused pins that a grant of an automount point
// the platform's automounter populates on lookup (/net, /home on a
// stock host) is refused as unjudged: what a lookup there mounts is
// the map's to say. A host running no automounter has none to
// grant, and the test says so rather than demanding one: the
// Seatbelt row's demand does not cover it.
func TestAutomountGrantRefused(t *testing.T) {
	m, err := readMounts()
	if err != nil {
		t.Fatal(err)
	}
	var point string
	for _, p := range m.points {
		if m.untriggered(p) && p != "/" {
			point = p
			break
		}
	}
	if point == "" {
		t.Skipf("no untriggered automount on this host (mounts: %v)", m.types)
	}
	tree := rootTree(t)
	if err := os.MkdirAll(filepath.Join(tree, point), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = resolveWorld(Spec{Exec: "/payload", Root: tree, PathGrants: []PathGrant{{Path: point, Access: ReadWrite}}}, osRow)
	if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "an automount not yet triggered") {
		t.Fatalf("a grant of %s: %v, want refused as unjudged", point, err)
	}
}

// TestSocketGrantResolves pins that a grant of a unix socket, an
// entry no descriptor can be opened on, resolves to the kernel's
// spelling of its directory with its own name.
func TestSocketGrantResolves(t *testing.T) {
	tree := rootTree(t)
	dir, err := os.MkdirTemp("/tmp", "sandbox-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.MkdirAll(filepath.Join(tree, dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, sock), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := resolveWorld(Spec{Exec: "/payload", Root: tree, PathGrants: []PathGrant{{Path: sock, Access: ReadWrite}}}, osRow)
	if err != nil {
		t.Fatalf("a socket grant: %v", err)
	}
	if want := must(filepath.EvalSymlinks(dir)) + "/agent.sock"; len(w.binds) != 1 || w.binds[0].Target != want {
		t.Fatalf("a socket grant's target: %+v, want %s", w.binds, want)
	}
}

// TestRootLoadsTreeLibraries pins the entrypoint rule end to end
// with the platform's own toolchain: an image linked against a
// library in the tree, reached relative to the image, runs; one
// linked at an image-absolute path, or carrying such a run path, or
// built for another machine, is refused before anything runs.
func TestRootLoadsTreeLibraries(t *testing.T) {
	requireSeatbelt(t)
	clang, err := exec.LookPath("clang")
	if err != nil {
		testdemand.Live(t, "SANDBOX_TEST_REQUIRE_SEATBELT", "no clang on this host: "+err.Error())
	}
	tree := must(filepath.EvalSymlinks(t.TempDir()))
	src := filepath.Join(tree, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "x.c"), []byte("int answer(void) { return 42; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.c"), []byte("#include <stdio.h>\nint answer(void);\nint main(void) { printf(\"answer=%d\\n\", answer()); return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "alone.c"), []byte("int main(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := func(args ...string) {
		t.Helper()
		cmd := exec.Command(clang, args...)
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("clang %v: %v\n%s", args, err, out)
		}
	}
	build("-dynamiclib", "-install_name", "@rpath/libx.dylib", "-o", filepath.Join(tree, "libx.dylib"), "x.c")
	build("-o", filepath.Join(tree, "relative"), "main.c", filepath.Join(tree, "libx.dylib"), "-Wl,-rpath,@executable_path")
	build("-o", filepath.Join(tree, "hostrpath"), "main.c", filepath.Join(tree, "libx.dylib"), "-Wl,-rpath,/opt/elsewhere")
	build("-dynamiclib", "-install_name", "/opt/elsewhere/libabs.dylib", "-o", filepath.Join(tree, "libabs.dylib"), "x.c")
	build("-o", filepath.Join(tree, "absolute"), "main.c", filepath.Join(tree, "libabs.dylib"))
	other := "x86_64"
	if runtime.GOARCH == "amd64" {
		other = "arm64"
	}
	build("-arch", other, "-o", filepath.Join(tree, "foreign"), "alone.c")
	build("-arch", other, "-o", filepath.Join(tree, "foreign-bad"), "alone.c", "-Wl,-rpath,/opt/elsewhere")
	build("-o", filepath.Join(tree, "weak"), "main.c", "-Wl,-weak_library,"+filepath.Join(tree, "libabs.dylib"))
	build("-o", filepath.Join(tree, "upward"), "main.c", "-Wl,-upward_library,"+filepath.Join(tree, "libabs.dylib"))
	build("-dynamiclib", "-install_name", "@rpath/libre.dylib", "-o", filepath.Join(tree, "libre.dylib"), "x.c", "-Wl,-reexport_library,"+filepath.Join(tree, "libabs.dylib"))
	build("-o", filepath.Join(tree, "dyldenv"), "alone.c", "-Wl,-dyld_env,DYLD_LIBRARY_PATH=/opt/elsewhere")
	// Universal images whose slices disagree, assembled here so the
	// slices' order is the test's: the native slice is the one judged
	// — clean beside a bad foreign one runs, bad beside a clean
	// foreign one is refused — found by its machine, never by its
	// place, the native slice last in one image and first in the
	// other.
	universal(t, filepath.Join(tree, "universal"), filepath.Join(tree, "foreign-bad"), filepath.Join(tree, "relative"))
	universal(t, filepath.Join(tree, "universal-bad"), filepath.Join(tree, "hostrpath"), filepath.Join(tree, "foreign"))
	out := &output{}
	sb, st := run(t, Spec{Exec: "/relative", Root: tree, Env: []string{}, Stdout: out, Stderr: os.Stderr})
	if st.Code != 0 || facts(out.String())["answer"] != "42" || sb.Tier() != OS {
		t.Fatalf("an image loading the tree's library: exit %+v, output %q", st, out.String())
	}
	out = &output{}
	if _, st := run(t, Spec{Exec: "/universal", Root: tree, Env: []string{}, Stdout: out, Stderr: os.Stderr}); st.Code != 0 || facts(out.String())["answer"] != "42" {
		t.Fatalf("a universal image's native slice: exit %+v, output %q", st, out.String())
	}
	refusals := map[string]string{
		"/hostrpath":   "a run path",
		"/absolute":    "image-absolute",
		"/foreign":     "built for",
		"/weak":        "weakly linked",
		"/upward":      "image-absolute", // ld records an executable's upward link as a plain load; the upward arm is TestLoadPath's
		"/libre.dylib": "not an executable",
		"/dyldenv":     "loader environment",
	}
	refusals["/universal-bad"] = "a run path"
	for name, want := range refusals {
		sb, err := New(Spec{Exec: name, Root: tree, Env: []string{}})
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q refused", name, err, want)
			sb.Destroy()
		}
	}
}

// TestRootRefusals pins what the Root world refuses before anything
// runs: an entrypoint that is no Mach-O image (a script), a grant
// with no target in the tree, and the undeliverable intents the
// shared tree resolution names.
func TestRootRefusals(t *testing.T) {
	requireSeatbelt(t)
	tree := rootTree(t)
	if err := os.WriteFile(filepath.Join(tree, "script"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, spec := range map[string]Spec{
		"a script":                   {Exec: "/script", Root: tree},
		"a missing entrypoint":       {Exec: "/nope", Root: tree},
		"a grant absent in the tree": {Exec: "/payload", Root: tree, PathGrants: []PathGrant{{Path: must(filepath.EvalSymlinks(t.TempDir())), Access: ReadWrite}}},
		"a hostname":                 {Exec: "/payload", Root: tree, Hostname: "box"},
		"a root that is a file":      {Exec: "/payload", Root: filepath.Join(tree, "etc", "tree-marker")},
	} {
		spec.Env = []string{childEnv + "=hello"}
		sb, err := New(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) {
			t.Errorf("%s: %v, want ErrUndeliverable", name, err)
			sb.Destroy()
		}
	}
}

// TestImageRelative pins the entrypoint rule's reading of a library
// path: the substrate's and the image-relative admitted, an
// image-absolute path elsewhere not.
func TestImageRelative(t *testing.T) {
	for p, want := range map[string]bool{
		"/usr/lib/libSystem.B.dylib":                                         true,
		"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": true,
		"@executable_path/../lib/libfoo.dylib":                               true,
		"@loader_path/libbar.dylib":                                          true,
		"@rpath/libbaz.dylib":                                                true,
		"/opt/homebrew/lib/libfoo.dylib":                                     false,
		"/usr/local/lib/libfoo.dylib":                                        false,
		"/lib/libc.dylib":                                                    false,
	} {
		if got := imageRelative(p); got != want {
			t.Errorf("imageRelative(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestCheckMachO pins the entrypoint check on this binary (libSystem
// alone) and on a script.
func TestCheckMachO(t *testing.T) {
	if err := checkMachO(must(os.Executable())); err != nil {
		t.Fatalf("this binary: %v", err)
	}
	script := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkMachO(script); err == nil || !strings.Contains(err.Error(), "Mach-O") {
		t.Fatalf("a script: %v", err)
	}
}

// TestSBPLString pins the profile's quoting.
func TestSBPLString(t *testing.T) {
	for in, want := range map[string]string{
		"/plain/path":   `"/plain/path"`,
		`/with "quote"`: `"/with \"quote\""`,
		`/back\slash`:   `"/back\\slash"`,
		"/café":         "\"/café\"",
	} {
		got, err := sbplString(in)
		if err != nil || got != want {
			t.Errorf("sbplString(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"/control\x01", "/bad\xff"} {
		if _, err := sbplString(in); err == nil {
			t.Errorf("sbplString(%q) accepted", in)
		}
	}
}

// TestLoadPath pins the reading of the loader commands debug/macho
// leaves raw: each command's name at the offset its header names, in
// either byte order, and an offset past the command read as no name.
func TestLoadPath(t *testing.T) {
	command := func(order binary.ByteOrder, cmd uint32, header int, name string) macho.LoadBytes {
		size := header + len(name) + 1
		size += (8 - size%8) % 8
		raw := make([]byte, size)
		order.PutUint32(raw[0:4], cmd)
		order.PutUint32(raw[4:8], uint32(size))
		order.PutUint32(raw[8:12], uint32(header))
		copy(raw[header:], name)
		return macho.LoadBytes(raw)
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		f := &macho.File{ByteOrder: order}
		for _, c := range []struct {
			cmd    uint32
			header int
			what   string
		}{
			{loadWeakDylib, 24, "weakly linked against"},
			{loadReexport, 24, "re-exporting"},
			{loadLazyDylib, 24, "lazily linked against"},
			{loadUpwardDylib, 24, "linked upward against"},
			{loadDylinker, 12, "loaded by"},
			{loadDyldEnv, 12, "a loader environment"},
		} {
			name, what, ok := loadPath(f, command(order, c.cmd, c.header, "/opt/x"))
			if !ok || what != c.what || name != "/opt/x" {
				t.Errorf("%v command %#x: %q %q %v", order, c.cmd, name, what, ok)
			}
		}
		if name, _, ok := loadPath(f, macho.LoadBytes([]byte{0, 0, 0, 0})); ok || name != "" {
			t.Errorf("%v a short command read as %q %v", order, name, ok)
		}
		raw := command(order, loadWeakDylib, 24, "/opt/x")
		order.PutUint32(raw[8:12], 1000)
		if name, _, ok := loadPath(f, raw); !ok || name != "" {
			t.Errorf("%v an offset past the command read as %q %v", order, name, ok)
		}
		if _, _, ok := loadPath(f, command(order, 0x1d, 12, "x")); ok {
			t.Errorf("%v a command naming nothing read as a path", order)
		}
	}
}

// universal writes a universal image holding the thin images in the
// order given: the fat header and one entry per slice, each slice at
// an offset aligned to its page.
func universal(t *testing.T, out string, slices ...string) {
	t.Helper()
	const align = 14 // 2^14, the arm64 slice's page
	var header bytes.Buffer
	binary.Write(&header, binary.BigEndian, uint32(0xcafebabe))
	binary.Write(&header, binary.BigEndian, uint32(len(slices)))
	offset := uint32(8 + 20*len(slices))
	var body [][]byte
	for _, p := range slices {
		b := must(os.ReadFile(p))
		f := must(macho.Open(p))
		f.Close()
		offset = (offset + (1 << align) - 1) &^ ((1 << align) - 1)
		for _, v := range []uint32{uint32(f.Cpu), f.SubCpu, offset, uint32(len(b)), align} {
			binary.Write(&header, binary.BigEndian, v)
		}
		body = append(body, b)
		offset += uint32(len(b))
	}
	file := header.Bytes()
	for _, b := range body {
		pad := (len(file) + (1 << align) - 1) &^ ((1 << align) - 1)
		file = append(file, make([]byte, pad-len(file))...)
		file = append(file, b...)
	}
	if err := os.WriteFile(out, file, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestProfileRules pins the Root profile's text where a host's own
// refusal would hide a rule's effect: the cores denial after the
// substrate's import (the last matching rule winning), the
// deny-by-default opening, and nothing re-admitting /cores.
func TestProfileRules(t *testing.T) {
	w := world{root: "/tree", binds: []bind{{Source: "/g", Target: "/g"}}, runtime: ""}
	p, err := profile(Spec{Root: "/tree"}, w, "/self")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(p), "\n")
	if len(lines) < 4 {
		t.Fatalf("the profile is %d lines: %q", len(lines), p)
	}
	if lines[0] != "(version 1)" || lines[1] != "(deny default)" || lines[2] != `(import "system.sb")` {
		t.Fatalf("the profile opens %q", lines[:3])
	}
	if lines[3] != `(deny file-write* (subpath "/cores"))` {
		t.Fatalf("the cores denial not right after the import: %q", lines[3])
	}
	for _, l := range lines[4:] {
		// A later rule re-admits /cores by naming it or by allowing an
		// ancestor: the root is its only one.
		if strings.Contains(l, "/cores") || strings.Contains(l, `"/"`) {
			t.Fatalf("a later rule reaches /cores: %q", l)
		}
	}
}
