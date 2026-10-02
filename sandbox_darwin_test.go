//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	case "rlimits":
		for _, r := range []struct {
			name string
			res  int
		}{{"cpu", unix.RLIMIT_CPU}, {"nofile", unix.RLIMIT_NOFILE}, {"nproc", unix.RLIMIT_NPROC}} {
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

// payload is a spec running this binary as the payload in the named
// mode, its output captured.
func payload(mode string, env ...string) (Spec, *bytes.Buffer) {
	var out bytes.Buffer
	return Spec{
		Exec:   must(os.Executable()),
		Env:    append([]string{childEnv + "=" + mode}, env...),
		Stdout: &out,
		Stderr: os.Stderr,
	}, &out
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

// TestOSRowReadOnlyGrant pins a read-only grant on the OS row: its
// writes denied throughout, a write beside it untouched.
func TestOSRowReadOnlyGrant(t *testing.T) {
	requireSeatbelt(t)
	ro := must(filepath.EvalSymlinks(t.TempDir()))
	rw := must(filepath.EvalSymlinks(t.TempDir()))
	if err := os.Mkdir(filepath.Join(ro, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec, out := payload("write", "SANDBOX_TEST_WRITE="+filepath.Join(ro, "sub", "w"))
	spec.PathGrants = []PathGrant{{Path: ro, Access: ReadOnly}}
	if _, st := run(t, spec); st.Code != 0 || !strings.Contains(facts(out.String())["write"], "operation not permitted") {
		t.Fatalf("a write under the read-only grant: exit %+v, write=%q", st, facts(out.String())["write"])
	}
	spec, out = payload("write", "SANDBOX_TEST_WRITE="+filepath.Join(rw, "w"))
	spec.PathGrants = []PathGrant{{Path: ro, Access: ReadOnly}}
	if _, st := run(t, spec); st.Code != 0 || facts(out.String())["write"] != "<nil>" {
		t.Fatalf("a write beside the grant: exit %+v, write=%q", st, facts(out.String())["write"])
	}
}

// TestRlimitsApplied pins the kernel's bounds reaching the payload,
// and the working directory entered.
func TestRlimitsApplied(t *testing.T) {
	wd := must(filepath.EvalSymlinks(t.TempDir()))
	spec, out := payload("rlimits")
	spec.Limits = Limits{CPUSeconds: 100, MaxFiles: 300, MaxProcs: 500}
	spec.WorkDir = wd
	sb, st := run(t, spec)
	f := facts(out.String())
	if st.Code != 0 || f["cpu"] != "100" || f["nofile"] != "300" || f["nproc"] != "500" || f["cwd"] != wd {
		t.Fatalf("exit %+v, facts %v", st, f)
	}
	stats, err := sb.Stats()
	if err != nil || stats.Accounting != AccountingRlimits {
		t.Fatalf("stats %+v %v, want rlimits", stats, err)
	}
}

// TestMemoryWatchdogKillsHog pins the memory bound: a payload holding
// four times the bound is killed by the watchdog, after its
// announcement, and the account says so.
func TestMemoryWatchdogKillsHog(t *testing.T) {
	spec, out := payload("hog")
	spec.Limits = Limits{MemoryBytes: 64 << 20}
	sb, st := run(t, spec)
	if !st.Signaled || st.Signal != syscall.SIGKILL {
		t.Fatalf("exit %+v, output %q; want a kill", st, out.String())
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

// TestClassifyStatus pins the status pipe's reading, shared with the
// Linux rows.
func TestClassifyStatus(t *testing.T) {
	for in, want := range map[string]initOutcome{
		"":                      initDied,
		statusExecing:           initExeced,
		statusFailed + "why":    initRefused,
		statusApplyFailed + "x": initApplyFailed,
		"junk":                  initGarbled,
	} {
		if got, _ := classifyStatus([]byte(in)); got != want {
			t.Errorf("classifyStatus(%q) = %v, want %v", in, got, want)
		}
	}
}
