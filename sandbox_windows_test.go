//go:build windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/greatliontech/sandbox/internal/testdemand"
	"golang.org/x/sys/windows"
)

// childEnv marks this binary run as a test payload, in the named mode.
const childEnv = "SANDBOX_TEST_CHILD"

// TestMain runs this binary as the payload where the marker names a
// mode, the tests' own process otherwise.
func TestMain(m *testing.M) {
	if mode := os.Getenv(childEnv); mode != "" {
		child(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func child(mode string) {
	say := func(k string, v any) { fmt.Printf("%s=%v\n", k, v) }
	switch mode {
	case "hello":
		say("hello", "world")
		say("env", len(os.Environ()))
		say("host-only", os.Getenv("SANDBOX_TEST_HOST_ONLY"))
		say("systemroot", os.Getenv("SystemRoot"))
		wd, _ := os.Getwd()
		say("cwd", wd)
	case "exit7":
		os.Exit(7)
	case "probe":
		say("appcontainer", tokenDword(29))
		exe, _ := os.Executable()
		_, err := os.ReadDir(filepath.Dir(exe))
		say("read-own-dir", err)
		home, _ := os.UserHomeDir()
		_, err = os.ReadDir(home)
		say("read-home", err)
		_, err = os.ReadFile(`C:\Windows\System32\kernel32.dll`)
		say("read-system", err)
		for _, kv := range os.Environ() {
			if strings.HasPrefix(strings.ToUpper(kv), "LOCALAPPDATA=") {
				say("localappdata", "set")
			}
		}
	case "grants":
		ro, rw := os.Getenv("SANDBOX_TEST_RO"), os.Getenv("SANDBOX_TEST_RW")
		_, err := os.ReadFile(filepath.Join(ro, "f"))
		say("read-ro", err)
		say("write-ro", os.WriteFile(filepath.Join(ro, "w"), []byte("x"), 0o644))
		say("write-rw", os.WriteFile(filepath.Join(rw, "w"), []byte("x"), 0o644))
		_, err = os.ReadDir(os.Getenv("SANDBOX_TEST_OUTSIDE"))
		say("read-outside", err)
	case "net":
		c, err := net.DialTimeout("tcp", os.Getenv("SANDBOX_TEST_ADDR"), 5*time.Second)
		if c != nil {
			c.Close()
		}
		say("dial", err)
	case "hog":
		say("hog", "start")
		var bufs [][]byte
		for i := 0; i < 8; i++ {
			b := make([]byte, 64<<20)
			for j := range b {
				b[j] = byte(j)
			}
			bufs = append(bufs, b)
		}
		say("hogged", len(bufs))
	case "spin":
		say("spin", "start")
		end := time.Now().Add(20 * time.Second)
		for x := 0; time.Now().Before(end); x++ {
		}
		say("spun", "yes")
	case "spawn":
		exe, _ := os.Executable()
		n := 0
		for i := 0; i < 3; i++ {
			p, err := os.StartProcess(exe, []string{exe}, &os.ProcAttr{Env: []string{childEnv + "=sleep", "LOCALAPPDATA=" + os.Getenv("LOCALAPPDATA")}, Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
			if err != nil {
				say("spawn-"+strconv.Itoa(i), err)
				continue
			}
			n++
			say("child", p.Pid)
		}
		say("spawned", n)
		time.Sleep(20 * time.Second)
	case "echo":
		b, _ := io.ReadAll(os.Stdin)
		say("echoed", strings.TrimSpace(string(b)))
	case "runtime":
		say("write-runtime", os.WriteFile(filepath.Join(os.Getenv("SANDBOX_TEST_RUNTIME"), "w"), []byte("x"), 0o644))
	case "repermission":
		// A payload turning a read-write grant's permissions to its own
		// ends: refused, the grant carrying no right to.
		err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), os.Getenv("SANDBOX_TEST_RW"), "/grant", "Everyone:(F)").Run()
		say("repermission", err)
	case "sleep":
		time.Sleep(20 * time.Second)
	}
}

func tokenDword(class uint32) string {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); err != nil {
		return err.Error()
	}
	defer t.Close()
	var v, n uint32
	if err := windows.GetTokenInformation(t, class, (*byte)(unsafe.Pointer(&v)), 4, &n); err != nil {
		return err.Error()
	}
	return strconv.Itoa(int(v))
}

// facts parses the payload's "key=value" lines.
func facts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// payload is a spec running this binary as the payload in the named
// mode, its output captured, the network granted and a bound stated
// so that every row runs it.
func payload(mode string, env ...string) (Spec, *output) {
	out := &output{}
	exe, _ := os.Executable()
	return Spec{Exec: exe, Env: append([]string{childEnv + "=" + mode}, env...), Network: true, Limits: Limits{CPUSeconds: 60}, Stdout: out, Stderr: out}, out
}

// requireAppContainer skips where the host reaches no AppContainer,
// unless SANDBOX_TEST_REQUIRE_APPCONTAINER demands the row.
func requireAppContainer(t testing.TB) {
	t.Helper()
	facts, err := hostFactsFor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unavailable := ""
	if facts.appContainer != nil {
		unavailable = facts.appContainer.Error()
	}
	testdemand.Live(t, "SANDBOX_TEST_REQUIRE_APPCONTAINER", unavailable)
}

// overrideMinimal makes every row selection reach the Minimal row for
// the test's duration.
func overrideMinimal(t testing.TB) {
	t.Helper()
	hostOverride = &hostFacts{appContainer: errors.New("forced")}
	t.Cleanup(func() { hostOverride = nil })
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

// TestReachIsStartsSelection pins Reach as Start's selection: the OS
// row where the host makes an AppContainer, the Minimal row where it
// does not.
func TestReachIsStartsSelection(t *testing.T) {
	requireAppContainer(t)
	tier, lacking, err := Reach(context.Background(), Spec{})
	if err != nil || tier != OS || len(lacking) != 0 {
		t.Fatalf("Reach = %v %v %v, want the OS row", tier, lacking, err)
	}
	overrideMinimal(t)
	tier, lacking, err = Reach(context.Background(), Spec{})
	if err != nil || tier != Minimal || len(lacking) != 1 {
		t.Fatalf("Reach = %v %v %v, want the Minimal row below a forced facts", tier, lacking, err)
	}
}

// TestHelloUnderTheContainer pins the OS row's run: the payload runs
// under an AppContainer with the stated environment and the
// variables the platform's own machinery reads (LOCALAPPDATA and
// SystemRoot, with the temporary directory's two the launch adds)
// and nothing else of the host's, in the stated working directory,
// reads its own directory and the system's files and nothing of the
// user's, and reports the row.
func TestHelloUnderTheContainer(t *testing.T) {
	requireAppContainer(t)
	t.Setenv("SANDBOX_TEST_HOST_ONLY", "leaked")
	spec, out := payload("hello")
	spec.WorkDir = os.TempDir()
	sb, st := run(t, spec)
	f := facts(out.String())
	if st.Code != 0 || f["hello"] != "world" || f["host-only"] != "" || f["systemroot"] == "" || !strings.EqualFold(f["cwd"], os.TempDir()) || sb.Tier() != OS {
		t.Fatalf("exit %+v, facts %v, tier %v", st, f, sb.Tier())
	}
	if n, _ := strconv.Atoi(f["env"]); n < 3 || n > 5 {
		t.Fatalf("env held %s entries, want the stated one, the two carried and at most the temporary directory's two", f["env"])
	}
	spec, out = payload("probe")
	_, st = run(t, spec)
	f = facts(out.String())
	if st.Code != 0 || f["appcontainer"] != "1" || f["read-own-dir"] != "<nil>" || f["read-system"] != "<nil>" || f["read-home"] == "<nil>" || f["localappdata"] != "set" {
		t.Fatalf("exit %+v, facts %v; want a container reading its own directory and the system, not the user's", st, f)
	}
}

// TestExitCodeReported pins the payload's own exit code, never a
// signal on this platform.
func TestExitCodeReported(t *testing.T) {
	requireAppContainer(t)
	spec, _ := payload("exit7")
	_, st := run(t, spec)
	if st.Code != 7 || st.Signaled {
		t.Fatalf("exit %+v, want code 7, unsignaled", st)
	}
}

// TestGrantsRespected pins the grants: a read-only grant read and not
// written, a read-write grant written, a directory granted nothing
// unread; and after the run the granted entries carry no entry for
// the run's container.
func TestGrantsRespected(t *testing.T) {
	requireAppContainer(t)
	ro, rw, outside := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(ro, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, out := payload("grants", "SANDBOX_TEST_RO="+ro, "SANDBOX_TEST_RW="+rw, "SANDBOX_TEST_OUTSIDE="+outside)
	spec.PathGrants = []PathGrant{{Path: ro, Access: ReadOnly}, {Path: rw, Access: ReadWrite}}
	sb, st := run(t, spec)
	f := facts(out.String())
	if st.Code != 0 || f["read-ro"] != "<nil>" || f["write-ro"] == "<nil>" || f["write-rw"] != "<nil>" || f["read-outside"] == "<nil>" {
		t.Fatalf("exit %+v, facts %v", st, f)
	}
	for _, p := range []string{ro, rw} {
		if entries(t, p) != 0 {
			t.Errorf("%s still carries the container after the run", p)
		}
	}
	_ = sb
}

// entries counts the entries of a path's descriptor for a package
// identity (an AppContainer's SID, S-1-15-2-...), walking the ACL's
// own layout: the header, then each ACE with its SID after the mask.
func entries(t *testing.T, path string) int {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if acl == nil {
		return 0
	}
	n := 0
	p := unsafe.Pointer(acl)
	ace := unsafe.Add(p, unsafe.Sizeof(*acl))
	for i := 0; i < int(acl.AceCount); i++ {
		h := (*windows.ACE_HEADER)(ace)
		if h.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			a := (*windows.ACCESS_ALLOWED_ACE)(ace)
			sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
			if strings.HasPrefix(sid.String(), "S-1-15-2-") {
				n++
			}
		}
		ace = unsafe.Add(ace, h.AceSize)
	}
	return n
}

// TestRunReleasesWhatItHeld pins the run's end: the entrypoint's
// directory and the rendezvous directory carry no entry for the
// container after the run, and the profile's package directory is
// gone with the profile.
func TestRunReleasesWhatItHeld(t *testing.T) {
	requireAppContainer(t)
	rt := t.TempDir()
	spec, out := payload("runtime", "SANDBOX_TEST_RUNTIME="+rt)
	spec.RuntimeDir = rt
	sb, st := run(t, spec)
	if st.Code != 0 || facts(out.String())["write-runtime"] != "<nil>" {
		t.Fatalf("exit %+v, facts %v; want the rendezvous directory written", st, facts(out.String()))
	}
	exe, _ := os.Executable()
	for _, p := range []string{filepath.Dir(exe), rt} {
		if entries(t, p) != 0 {
			t.Errorf("%s still carries a container after the run", p)
		}
	}
	name := sb.(*windowsSandbox).profile.name
	if name != "" {
		t.Errorf("the profile %s outlived the run", name)
	}
	if dirs, _ := filepath.Glob(filepath.Join(os.Getenv("LOCALAPPDATA"), "Packages", "sandbox-run-*")); len(dirs) != 0 {
		t.Errorf("package directories outlive their runs: %v", dirs)
	}
}

// TestDestroyDuringWait pins Destroy against a Wait in progress: the
// run is killed and both callers see its end.
func TestDestroyDuringWait(t *testing.T) {
	requireAppContainer(t)
	spec, _ := payload("sleep")
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	type reaped struct {
		st  ExitStatus
		err error
	}
	waited := make(chan reaped, 1)
	go func() {
		st, err := sb.Wait()
		waited <- reaped{st, err}
	}()
	time.Sleep(200 * time.Millisecond)
	if err := sb.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	select {
	case r := <-waited:
		if r.err != nil || r.st.Code != killExitCode {
			t.Fatalf("Wait = %+v %v, want the kill", r.st, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Wait outlived Destroy")
	}
}

// TestEndedContextRefusesStart pins the wall clock as the caller's: a
// context ended before Start refuses, nothing running.
func TestEndedContextRefusesStart(t *testing.T) {
	requireAppContainer(t)
	spec, out := payload("hello")
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sb.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v, want the context's end", err)
	}
	if out.Len() != 0 {
		t.Fatalf("something ran: %q", out.String())
	}
}

// TestStreamsCopied pins the standard streams: a reader's bytes reach
// the payload's input, a file of the host's own takes its output.
func TestStreamsCopied(t *testing.T) {
	requireAppContainer(t)
	spec, out := payload("echo")
	spec.Stdin = strings.NewReader("from the caller\n")
	_, st := run(t, spec)
	if st.Code != 0 || facts(out.String())["echoed"] != "from the caller" {
		t.Fatalf("exit %+v, output %q", st, out.String())
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	spec, _ = payload("hello")
	spec.Stdout = f
	spec.Stderr = f
	_, st = run(t, spec)
	b, _ := os.ReadFile(f.Name())
	if st.Code != 0 || facts(string(b))["hello"] != "world" {
		t.Fatalf("exit %+v, file %q", st, b)
	}
}

// TestGrantCarriesNoPermissionRight pins a read-write grant's
// rights: data written and entries made, never the permissions
// changed.
func TestGrantCarriesNoPermissionRight(t *testing.T) {
	requireAppContainer(t)
	rw := t.TempDir()
	spec, out := payload("repermission", "SANDBOX_TEST_RW="+rw)
	spec.PathGrants = []PathGrant{{Path: rw, Access: ReadWrite}}
	_, st := run(t, spec)
	if st.Code != 0 || facts(out.String())["repermission"] == "<nil>" {
		t.Fatalf("exit %+v, facts %v; want the permission change refused", st, facts(out.String()))
	}
}

// TestOverlapJudgedByIdentity pins overlap on the entries named: a
// case variant and a short name of one grant are the one entry.
func TestOverlapJudgedByIdentity(t *testing.T) {
	requireAppContainer(t)
	d := t.TempDir()
	inner := filepath.Join(d, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	variants := map[string]string{"a case variant": strings.ToUpper(d)}
	if short, err := shortPath(d); err == nil && !strings.EqualFold(short, d) {
		variants["a short name"] = short
	}
	for name, alias := range variants {
		spec, _ := payload("hello")
		spec.PathGrants = []PathGrant{{Path: inner, Access: ReadOnly}, {Path: alias, Access: ReadWrite}}
		sb, err := New(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "overlap") {
			t.Errorf("%s of a grant over another: %v, want refused as overlapping", name, err)
			sb.Destroy()
		}
	}
}

// shortPath is the platform's short (8.3) spelling of a path.
func shortPath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var buf [windows.MAX_PATH]uint16
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// TestNetworkDeniedUnlessGranted pins the network: a container dials
// nothing unless the network is granted — and never an address of
// the host's own, loopback or interface, which the platform keeps
// from every package, so the witness is an endpoint off the host
// (the runner reaches it for its own work).
func TestNetworkDeniedUnlessGranted(t *testing.T) {
	requireAppContainer(t)
	if _, err := net.DialTimeout("tcp", offHost, 5*time.Second); err != nil {
		testdemand.Live(t, "SANDBOX_TEST_REQUIRE_APPCONTAINER", "no network to "+offHost+" from this host: "+err.Error())
	}
	for _, network := range []bool{false, true} {
		spec, out := payload("net", "SANDBOX_TEST_ADDR="+offHost)
		spec.Network = network
		_, st := run(t, spec)
		dialed := facts(out.String())["dial"] == "<nil>"
		if st.Code != 0 || dialed != network {
			t.Fatalf("network=%v: exit %+v, dial %q", network, st, facts(out.String())["dial"])
		}
	}
}

// offHost is an endpoint off the host for the network's witness.
const offHost = "github.com:443"

// TestMemoryBoundKillsHog pins the memory bound: a payload past it is
// ended by the Job's refused commit — killed on the Job's report, or
// dead of the refusal first, as this binary's race runtime is — and
// the account says the bound did it.
func TestMemoryBoundKillsHog(t *testing.T) {
	requireAppContainer(t)
	spec, out := payload("hog")
	spec.Limits = Limits{MemoryBytes: 256 << 20}
	sb, st := run(t, spec)
	f := facts(out.String())
	if st.Code == 0 || f["hogged"] != "" {
		t.Fatalf("exit %+v, facts %v; want the run ended past the bound", st, f)
	}
	stats, err := sb.Stats()
	if err != nil || stats.Accounting != AccountingJobObject || stats.MemoryKills != 1 || stats.CPUKills != 0 || stats.MemoryPeakBytes < 128<<20 {
		t.Fatalf("stats %+v %v, want the Job's enforcement of the memory bound", stats, err)
	}
}

// TestCPUBoundKillsSpinner pins the CPU bound: a spinning payload is
// killed by the watchdog's sample of the Job's account, well before
// the Job's own time limit would.
func TestCPUBoundKillsSpinner(t *testing.T) {
	requireAppContainer(t)
	spec, out := payload("spin")
	spec.Limits = Limits{CPUSeconds: 1}
	start := time.Now()
	sb, st := run(t, spec)
	if st.Code != killExitCode || facts(out.String())["spun"] == "yes" {
		t.Fatalf("exit %+v after %v, output %q; want a kill", st, time.Since(start), out.String())
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the kill took %v", elapsed)
	}
	if stats, err := sb.Stats(); err != nil || stats.CPUKills != 1 || stats.MemoryKills != 0 {
		t.Fatalf("stats %+v %v, want the kill by the CPU bound", stats, err)
	}
}

// TestProcessBoundRefusesSpawn pins the process bound: the Job
// refuses the process past the limit, counted.
func TestProcessBoundRefusesSpawn(t *testing.T) {
	requireAppContainer(t)
	spec, out := payload("spawn")
	spec.Limits = Limits{MaxProcs: 2}
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
	for facts(out.String())["spawned"] == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	f := facts(out.String())
	if f["spawned"] != "1" {
		t.Fatalf("spawned %q of three, want one under a bound of two: %q", f["spawned"], out.String())
	}
	stats, err := sb.Stats()
	if err != nil || stats.ForksRefused < 2 {
		t.Fatalf("stats %+v %v, want the refusals counted", stats, err)
	}
	cancel()
	if st, err := sb.Wait(); err != nil || st.Code != killExitCode {
		t.Fatalf("Wait after cancel: %+v %v", st, err)
	}
}

// TestCancelKillsJob pins the kill tie: cancellation ends the run's
// Job, a child the payload spawned included.
func TestCancelKillsJob(t *testing.T) {
	requireAppContainer(t)
	spec, out := payload("spawn")
	spec.Limits = Limits{MaxProcs: 5}
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
	for facts(out.String())["spawned"] == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	pid, err := strconv.Atoi(facts(out.String())["child"])
	if err != nil {
		t.Fatalf("the payload named no child: %q", out.String())
	}
	cancel()
	if st, err := sb.Wait(); err != nil || st.Code != killExitCode {
		t.Fatalf("Wait after cancel: %+v %v", st, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return
		}
		var code uint32
		windows.GetExitCodeProcess(h, &code)
		windows.CloseHandle(h)
		if code != 259 { // STILL_ACTIVE
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the child %d outlived the cancellation", pid)
}

// TestSignalKillsPayloadAlone pins Signal: os.Kill ends the payload,
// any other signal is refused as undeliverable.
func TestSignalKillsPayloadAlone(t *testing.T) {
	requireAppContainer(t)
	spec, _ := payload("sleep")
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := sb.Signal(os.Interrupt); !errors.Is(err, ErrUndeliverable) {
		t.Fatalf("Signal(interrupt) = %v, want refused", err)
	}
	if err := sb.Signal(os.Kill); err != nil {
		t.Fatal(err)
	}
	if st, err := sb.Wait(); err != nil || st.Code != killExitCode {
		t.Fatalf("Wait after kill: %+v %v", st, err)
	}
}

// TestStartRefusals pins what the rows refuse before anything runs.
func TestStartRefusals(t *testing.T) {
	requireAppContainer(t)
	for name, change := range map[string]func(*Spec){
		"a hostname":         func(s *Spec) { s.Hostname = "box" },
		"a Root":             func(s *Spec) { s.Root = t.TempDir() },
		"an open-file bound": func(s *Spec) { s.Limits.MaxFiles = 64 },
		"a missing exec":     func(s *Spec) { s.Exec = filepath.Join(t.TempDir(), "nope.exe") },
		"a relative exec":    func(s *Spec) { s.Exec = "nope.exe" },
		"overlapping grants": func(s *Spec) {
			d := t.TempDir()
			os.Mkdir(filepath.Join(d, "in"), 0o755)
			s.PathGrants = []PathGrant{{Path: d}, {Path: filepath.Join(d, "in")}}
		},
	} {
		spec, _ := payload("hello")
		change(&spec)
		sb, err := New(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) {
			t.Errorf("%s: Start = %v, want ErrUndeliverable", name, err)
			sb.Destroy()
		}
	}
}

// TestMinimalRowRefusesBoundaries pins the Minimal row: bounds alone,
// so a Root, a denied network, a read-only grant and no limits are
// refused, and a bounded run goes.
func TestMinimalRowRefusesBoundaries(t *testing.T) {
	overrideMinimal(t)
	for name, change := range map[string]func(*Spec){
		"a denied network":  func(s *Spec) { s.Network = false },
		"a read-only grant": func(s *Spec) { s.PathGrants = []PathGrant{{Path: t.TempDir(), Access: ReadOnly}} },
		"no limits":         func(s *Spec) { s.Limits = Limits{} },
	} {
		spec, _ := payload("hello")
		change(&spec)
		sb, err := New(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) {
			t.Errorf("%s: Start = %v, want ErrUndeliverable", name, err)
			sb.Destroy()
		}
	}
	spec, out := payload("hello")
	sb, st := run(t, spec)
	if st.Code != 0 || facts(out.String())["hello"] != "world" || sb.Tier() != Minimal {
		t.Fatalf("exit %+v, output %q, tier %v; want the Minimal row's run", st, out.String(), sb.Tier())
	}
	spec, out = payload("hog")
	spec.Limits = Limits{MemoryBytes: 256 << 20}
	sb, st = run(t, spec)
	if st.Code == 0 || facts(out.String())["hogged"] != "" {
		t.Fatalf("exit %+v, output %q; want the Job's bound on the Minimal row", st, out.String())
	}
	if stats, err := sb.Stats(); err != nil || stats.MemoryKills != 1 {
		t.Fatalf("stats %+v %v", stats, err)
	}
}

// TestMinTierRefusesBeforeExec pins MinTier: a floor above the row
// reached refuses before anything runs.
func TestMinTierRefusesBeforeExec(t *testing.T) {
	overrideMinimal(t)
	spec, out := payload("hello")
	spec.MinTier = OS
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	var te *TierError
	if err := sb.Start(context.Background()); !errors.As(err, &te) || te.Reached != Minimal || te.Required != OS {
		t.Fatalf("Start = %v, want a tier refusal", err)
	}
	if out.Len() != 0 {
		t.Fatalf("something ran: %q", out.String())
	}
}

var _ = syscall.EscapeArg
