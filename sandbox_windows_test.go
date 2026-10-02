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
	mode := os.Getenv(childEnv)
	// The world mode rides the arguments: its run states no
	// environment, under a Root, and sees what the launch carries.
	if len(os.Args) > 1 && os.Args[1] == "world" {
		mode = "world"
	}
	if mode != "" {
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
	case "world":
		// The Root world: the tree read and executed at its host path,
		// never written; a grant and the rendezvous directory at
		// their host paths; the host beyond unread.
		tree, ro, rw, rt, outside := os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6]
		wd, _ := os.Getwd()
		say("cwd", wd)
		say("env", len(os.Environ()))
		_, err := os.ReadFile(filepath.Join(tree, "etc", "tree-marker"))
		say("readtree", err)
		_, err = os.ReadFile(filepath.Join(tree, "etc", "link-marker"))
		say("readlink", err)
		say("writetree", os.WriteFile(filepath.Join(tree, "etc", "w"), []byte("x"), 0o644))
		_, err = os.ReadFile(filepath.Join(outside, "secret"))
		say("readoutside", err)
		_, err = os.ReadFile(filepath.Join(ro, "f"))
		say("readro", err)
		say("writero", os.WriteFile(filepath.Join(ro, "w"), []byte("x"), 0o644))
		say("writerw", os.WriteFile(filepath.Join(rw, "w"), []byte("x"), 0o644))
		say("writert", os.WriteFile(filepath.Join(rt, "w"), []byte("x"), 0o644))
		runs := func(exe string) string {
			cmd := exec.Command(exe)
			cmd.Env = append(os.Environ(), childEnv+"=hello")
			// The child's input is this process's own: a package may
			// not open the null device by name, which os/exec would
			// for an unstated input.
			cmd.Stdin = os.Stdin
			out, err := cmd.Output()
			return fmt.Sprintf("%v:%s", err, strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]))
		}
		say("sibling", runs(filepath.Join(tree, "sibling.exe")))
		say("execout", runs(filepath.Join(outside, "payload.exe")))
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
// identity (an AppContainer's SID, S-1-15-2-...).
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
	n := 0
	for h, ace := range aces(acl) {
		if h.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		a := (*windows.ACCESS_ALLOWED_ACE)(ace)
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		if strings.HasPrefix(sid.String(), "S-1-15-2-") {
			n++
		}
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
	spec, out := payload("sleep")
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
			t.Fatalf("Wait = %+v %v, want the kill; the payload said %q", r.st, r.err, out.String())
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
	// A junction onto the grant's directory: its own parents are not
	// the grant's, its target's are.
	junction := filepath.Join(t.TempDir(), "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, d).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	variants["a junction"] = junction
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

// TestInheritanceStopsAtJunction pins the entries' propagation: a
// junction a payload could plant beneath a read-write grant, onto a
// directory outside the grants, carries no entry for the container
// while the run goes on.
func TestInheritanceStopsAtJunction(t *testing.T) {
	requireAppContainer(t)
	rw, outside := t.TempDir(), t.TempDir()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(rw, "j"), outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	spec, _ := payload("sleep")
	spec.PathGrants = []PathGrant{{Path: rw, Access: ReadWrite}}
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sb.Destroy()
	if n := entries(t, outside); n != 0 {
		t.Fatalf("the directory beyond the junction carries %d container entries during the run", n)
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
		"a root":            func(s *Spec) { s.Root, s.Exec = rootTree(t), "/payload.exe" },
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

// rootTree lays out a tree for a Root: this binary as the payload
// and as a sibling, a marker to read, directories to grant.
func rootTree(t *testing.T) string {
	t.Helper()
	tree := must(filepath.EvalSymlinks(t.TempDir()))
	b := must(os.ReadFile(must(os.Executable())))
	for _, name := range []string{"payload.exe", "sibling.exe"} {
		if err := os.WriteFile(filepath.Join(tree, name), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"etc", "grant-rw"} {
		if err := os.Mkdir(filepath.Join(tree, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tree, "etc", "tree-marker"), []byte("tree"), 0o644); err != nil {
		t.Fatal(err)
	}
	return tree
}

// link makes a symbolic link, or says the host lets this process
// make none (a privilege the platform grants administrators and
// developer mode).
func link(t *testing.T, target, name string) bool {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Logf("no symbolic link: %v", err)
		return false
	}
	return true
}

// TestRootWorld pins the OS row's world under a Root on this platform
// (docs/specs/sandbox.md, "Root is world-restriction"): the tree
// readable and executable at its host path, a link in it followed
// on the host, and nothing else of the host but what the platform
// grants every package; the tree never written; a read-only grant
// read, a read-write grant and the rendezvous directory written, at
// their host paths with no entry in the tree; the working directory
// the tree; the environment the stated one and what the launch
// carries.
func TestRootWorld(t *testing.T) {
	requireAppContainer(t)
	tree := rootTree(t)
	linked := link(t, filepath.Join("..", "etc", "tree-marker"), filepath.Join(tree, "etc", "link-marker"))
	outside := must(filepath.EvalSymlinks(t.TempDir()))
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "payload.exe"), must(os.ReadFile(must(os.Executable()))), 0o755); err != nil {
		t.Fatal(err)
	}
	ro, rw, rt := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(ro, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := &output{}
	spec := Spec{
		Exec:       "/payload.exe",
		Args:       []string{"world", tree, ro, rw, rt, outside},
		Env:        []string{"ONE=1", "TWO=2"},
		Root:       tree,
		PathGrants: []PathGrant{{Path: ro, Access: ReadOnly}, {Path: rw, Access: ReadWrite}},
		RuntimeDir: rt,
		Limits:     Limits{CPUSeconds: 60},
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
		if f[key] == "<nil>" {
			t.Errorf("%s = %q, want denied", key, f[key])
		}
	}
	allowed := func(key string) {
		t.Helper()
		if f[key] != "<nil>" {
			t.Errorf("%s = %q, want allowed", key, f[key])
		}
	}
	if !strings.EqualFold(f["cwd"], tree) {
		t.Errorf("cwd = %q, want the tree %q", f["cwd"], tree)
	}
	// The two stated, LOCALAPPDATA and SystemRoot carried, and at
	// most the temporary directory's two.
	if n, _ := strconv.Atoi(f["env"]); n < 4 || n > 6 {
		t.Errorf("env = %q entries, want the two stated and the launch's", f["env"])
	}
	allowed("readtree")
	if linked {
		allowed("readlink")
	}
	denied("writetree")
	denied("readoutside")
	allowed("readro")
	denied("writero")
	allowed("writerw")
	allowed("writert")
	if !strings.HasPrefix(f["sibling"], "<nil>:hello=world") {
		t.Errorf("sibling = %q, want the sibling executed", f["sibling"])
	}
	if strings.HasPrefix(f["execout"], "<nil>") {
		t.Errorf("execout = %q, want the host's binary refused", f["execout"])
	}
	if _, err := os.Stat(filepath.Join(tree, "etc", "w")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the tree was written: %v", err)
	}
	for _, p := range []string{tree, ro, rw, rt} {
		if entries(t, p) != 0 {
			t.Errorf("%s still carries the container after the run", p)
		}
	}
	// An unstated environment under a Root: empty but for what the
	// launch carries.
	out = &output{}
	spec.Env = nil
	spec.Stdout = out
	if _, st := run(t, spec); st.Code != 0 {
		t.Fatalf("unstated environment: exit %+v, output %q", st, out.String())
	}
	if n, _ := strconv.Atoi(facts(out.String())["env"]); n < 2 || n > 4 {
		t.Errorf("env = %q entries unstated, want the launch's alone", facts(out.String())["env"])
	}
	// A working directory stated with "..": clamped at the tree, the
	// directory delivered the tree's own under that name, never the
	// host's beside the tree.
	if err := os.Mkdir(filepath.Join(filepath.Dir(tree), "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	out = &output{}
	spec.WorkDir = "/../etc"
	spec.Stdout = out
	if _, st := run(t, spec); st.Code != 0 {
		t.Fatalf("workdir: exit %+v, output %q", st, out.String())
	}
	if cwd, want := facts(out.String())["cwd"], filepath.Join(tree, "etc"); !strings.EqualFold(cwd, want) {
		t.Errorf("cwd = %q, want %q", cwd, want)
	}
}

// TestRootJunctionsJudgedByTarget pins the judgement over a junction
// under a Root: a junction is its target's spelling, so a grant
// through one onto the tree lies within the tree, one onto another
// grant's subtree overlaps it, a working directory through one out
// of the tree leads out of it, and a Root spelled through one is the
// tree it leads to.
func TestRootJunctionsJudgedByTarget(t *testing.T) {
	requireAppContainer(t)
	tree := rootTree(t)
	junction := func(target string) string {
		t.Helper()
		j := filepath.Join(t.TempDir(), "j")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", j, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v %s", err, out)
		}
		return j
	}
	refused := func(name string, spec Spec, want string) {
		t.Helper()
		spec.Env = []string{childEnv + "=hello"}
		sb, err := New(spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want refused as %q", name, err, want)
			sb.Destroy()
		}
	}
	refused("a grant through a junction onto the tree", Spec{Exec: "/payload.exe", Root: tree, PathGrants: []PathGrant{{Path: junction(filepath.Join(tree, "grant-rw")), Access: ReadWrite}}}, "lies within the tree")
	d := t.TempDir()
	inner := filepath.Join(d, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	refused("a grant through a junction into another's subtree", Spec{Exec: "/payload.exe", Root: tree, PathGrants: []PathGrant{{Path: d, Access: ReadOnly}, {Path: junction(inner), Access: ReadWrite}}}, "overlap")
	outside := t.TempDir()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(tree, "w"), outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	refused("a working directory through a junction out of the tree", Spec{Exec: "/payload.exe", Root: tree, WorkDir: "/w"}, "leads out of the tree")
	spec, out := payload("hello")
	spec.Exec, spec.Root = "/payload.exe", filepath.Join(junction(filepath.Dir(tree)), filepath.Base(tree))
	if sb, st := run(t, spec); st.Code != 0 || facts(out.String())["hello"] != "world" || sb.Tier() != OS {
		t.Errorf("a Root through a junction: exit %+v, output %q, tier %v; want the tree it leads to", st, out.String(), sb.Tier())
	}
}

// TestRootRefusals pins what the Root world refuses before anything
// runs: a script or a library as the entrypoint, a missing one, one
// spelled as a host path, a link leading out of the tree, a
// hostname, a Root that is a file, a grant within the tree or
// holding it.
func TestRootRefusals(t *testing.T) {
	requireAppContainer(t)
	tree := rootTree(t)
	parent := filepath.Dir(tree)
	if err := os.WriteFile(filepath.Join(tree, "script.bat"), []byte("@echo hi\r\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "lib.dll"), must(os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll"))), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(must(filepath.EvalSymlinks(t.TempDir())), "payload.exe")
	if err := os.WriteFile(outside, must(os.ReadFile(must(os.Executable()))), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Spec{
		"a script":                 {Exec: "/script.bat", Root: tree},
		"a library":                {Exec: "/lib.dll", Root: tree},
		"a missing entrypoint":     {Exec: "/nope.exe", Root: tree},
		"a host path":              {Exec: filepath.Join(tree, "payload.exe"), Root: tree},
		"a hostname":               {Exec: "/payload.exe", Root: tree, Hostname: "box"},
		"a root that is a file":    {Exec: "/payload.exe", Root: filepath.Join(tree, "etc", "tree-marker")},
		"a grant within the tree":  {Exec: "/payload.exe", Root: tree, PathGrants: []PathGrant{{Path: filepath.Join(tree, "grant-rw"), Access: ReadWrite}}},
		"a grant holding the tree": {Exec: "/payload.exe", Root: tree, PathGrants: []PathGrant{{Path: parent, Access: ReadWrite}}},
	}
	if link(t, outside, filepath.Join(tree, "out.exe")) {
		cases["a link out of the tree"] = Spec{Exec: "/out.exe", Root: tree}
	}
	for name, spec := range cases {
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

// TestRootAliasedGrantsRefused pins the containment judged by
// identity under a Root: a grant of the tree's parent under another
// spelling (a case variant's, a junction's) holds the tree.
func TestRootAliasedGrantsRefused(t *testing.T) {
	requireAppContainer(t)
	parent := must(filepath.EvalSymlinks(t.TempDir()))
	tree := filepath.Join(parent, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "payload.exe"), must(os.ReadFile(must(os.Executable()))), 0o755); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(t.TempDir(), "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, parent).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	for name, alias := range map[string]string{"a case variant": strings.ToUpper(parent), "a junction": junction} {
		sb, err := New(Spec{Exec: "/payload.exe", Env: []string{childEnv + "=hello"}, Root: tree, PathGrants: []PathGrant{{Path: alias, Access: ReadWrite}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := sb.Start(context.Background()); !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "holds the tree") {
			t.Errorf("%s %s granted over the tree's parent: %v, want refused as holding the tree", name, alias, err)
			sb.Destroy()
		}
	}
}

// TestReachJudged pins the reach of a granted entry and beneath it,
// judged by the platform's own access check for the run's identity,
// against what the run can then do: a grant accepted is one whose
// entries the payload reads, and writes where read-write; an entry
// that keeps its own permissions is accepted where it allows every
// package what the grant carries and refused where it does not, or
// inherits nothing to what lies beneath it, or allows reading alone
// under a read-write grant; a grant's own entry denying the run
// (everyone's execution: what the grant carries) is refused ahead of
// the entry written for the run; a refused grant leaves no entry
// behind. An entry denied to every package is the kernel's to judge
// either way — it heeds no such denial for a package's identity, as
// the windows row witnessed — and the judgement must agree with the
// payload's reading.
func TestReachJudged(t *testing.T) {
	requireAppContainer(t)
	const allPackages = "*S-1-15-2-1"
	accepted, refused := true, false
	for name, c := range map[string]struct {
		under  string // "ro": the read-only grant's subdirectory; "rw": the read-write grant's; "grant": the read-only grant itself
		icacls []string
		want   *bool
	}{
		"a protected entry allowing every package":              {"ro", []string{"/inheritance:r", "/grant:r", allPackages + ":(OI)(CI)(RX)"}, &accepted},
		"a protected entry allowing nothing of it":              {"ro", []string{"/inheritance:r", "/grant:r", "*S-1-3-4:(OI)(CI)F"}, &refused},
		"a protected directory inheriting nothing":              {"ro", []string{"/inheritance:r", "/grant:r", allPackages + ":(RX)"}, &refused},
		"a protected directory inheriting only":                 {"ro", []string{"/inheritance:r", "/grant:r", allPackages + ":(OI)(CI)(IO)(RX)"}, &refused},
		"an entry denied to every package":                      {"ro", []string{"/deny", allPackages + ":(OI)(CI)(R)"}, nil},
		"a read-write grant holding entries":                    {"rw", nil, &accepted},
		"a protected entry read alone under a read-write grant": {"rw", []string{"/inheritance:r", "/grant:r", allPackages + ":(OI)(CI)(RX)"}, &refused},
		"a grant's own entry denied to everyone":                {"grant", []string{"/deny", "*S-1-1-0:(X)"}, &refused},
	} {
		t.Run(name, func(t *testing.T) {
			ro, rw := t.TempDir(), t.TempDir()
			target := map[string]string{"ro": filepath.Join(ro, "kept"), "rw": filepath.Join(rw, "kept"), "grant": ro}[c.under]
			if c.under != "grant" {
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(target, "f"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if c.icacls != nil {
				if out, err := exec.Command("icacls", append([]string{target}, c.icacls...)...).CombinedOutput(); err != nil {
					t.Fatalf("icacls: %v %s", err, out)
				}
				// The owner may always change a descriptor: the entry is
				// restored for the temporary directory's removal.
				t.Cleanup(func() { exec.Command("icacls", target, "/reset").Run() })
			}
			spec, out := payload("grants", "SANDBOX_TEST_RO="+filepath.Join(ro, "kept"), "SANDBOX_TEST_RW="+filepath.Join(rw, "kept"), "SANDBOX_TEST_OUTSIDE="+t.TempDir())
			if c.under == "grant" {
				spec.Env[1] = "SANDBOX_TEST_RO=" + ro
			}
			for _, d := range []string{filepath.Join(ro, "kept"), filepath.Join(rw, "kept")} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			spec.PathGrants = []PathGrant{{Path: ro, Access: ReadOnly}, {Path: rw, Access: ReadWrite}}
			sb, err := New(spec)
			if err != nil {
				t.Fatal(err)
			}
			err = sb.Start(context.Background())
			switch {
			case err == nil && c.want != nil && !*c.want:
				t.Errorf("Start accepted the grant, want it refused as not delivered whole")
				sb.Destroy()
			case err == nil:
				st, err := sb.Wait()
				if f := facts(out.String()); err != nil || st.Code != 0 || f["read-ro"] != "<nil>" || f["write-rw"] != "<nil>" {
					t.Errorf("the grants judged delivered, but the payload: exit %+v %v, read-ro %q, write-rw %q", st, err, f["read-ro"], f["write-rw"])
				}
			case c.want != nil && *c.want:
				t.Errorf("Start: %v, want the grants delivered", err)
			case !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "not delivered whole"):
				t.Errorf("Start: %v, want refused as not delivered whole", err)
			}
			for _, d := range []string{ro, rw} {
				if entries(t, d) != 0 {
					t.Errorf("%s still carries the container after the run", d)
				}
			}
		})
	}
}

// TestCheckPE pins the entrypoint check: this binary admitted, a
// library and a script refused.
func TestCheckPE(t *testing.T) {
	if err := checkPE(must(os.Executable())); err != nil {
		t.Fatalf("this binary: %v", err)
	}
	if err := checkPE(filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")); err == nil || !strings.Contains(err.Error(), "library") {
		t.Fatalf("a library: %v", err)
	}
	script := filepath.Join(t.TempDir(), "s.bat")
	if err := os.WriteFile(script, []byte("@echo hi\r\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkPE(script); err == nil || !strings.Contains(err.Error(), "not a PE image") {
		t.Fatalf("a script: %v", err)
	}
}
