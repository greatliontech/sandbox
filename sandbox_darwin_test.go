//go:build darwin

package sandbox

import (
	"bytes"
	"context"
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
	"sync"
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
	switch mode := os.Getenv(childEnv); mode {
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
	default:
		fmt.Fprintf(os.Stderr, "unknown child mode %q\n", mode)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// facts parses the payload's "key=value" lines.
func facts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
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

// withoutSeatbelt makes every selection in the test reach the Minimal
// row, the probe's answer set aside.
func withoutSeatbelt(t *testing.T) {
	t.Helper()
	hostOverride = &hostFacts{seatbelt: errors.New("sandbox-exec set aside for the test")}
	t.Cleanup(func() { hostOverride = nil })
}

// output is the payload's captured output, readable while the run's
// copier still writes it.
type output struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func (o *output) Len() int { return len(o.String()) }

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

func run(t *testing.T, spec Spec) (Sandbox, ExitStatus) {
	t.Helper()
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	return sb, st
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
		"a root":           func(s *Spec) { s.Root = t.TempDir() },
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
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) {
			t.Errorf("%s on the Minimal row: %v, want ErrUndeliverable", name, err)
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
	_, st := run(t, spec)
	if !st.Signaled || st.Signal != syscall.SIGKILL {
		t.Fatalf("exit %+v, output %q; want a kill", st, out.String())
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
	if err != nil || stats.Accounting != AccountingWatchdog || stats.MemoryKills != 1 || stats.MemoryPeakBytes <= 64<<20 {
		t.Fatalf("stats %+v %v, want the watchdog's kill past the bound", stats, err)
	}
}

// TestCPUWatchdogKillsSpinner pins the CPU bound behind the kernel's
// signal: a payload ignoring SIGXCPU is killed by the watchdog.
func TestCPUWatchdogKillsSpinner(t *testing.T) {
	spec, out := payload("spin")
	spec.Limits = Limits{CPUSeconds: 1}
	start := time.Now()
	_, st := run(t, spec)
	if !st.Signaled || st.Signal != syscall.SIGKILL || facts(out.String())["spun"] == "yes" {
		t.Fatalf("exit %+v after %v, output %q; want a kill", st, time.Since(start), out.String())
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("the kill took %v", elapsed)
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
		"a root":                func(s *Spec) { s.Root = t.TempDir() },
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
