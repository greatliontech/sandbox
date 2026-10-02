//go:build darwin

package spike

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDarwinFacts(t *testing.T) {
	if os.Getenv("SPIKE_CHILD") != "" {
		child()
		return
	}
	exe, _ := os.Executable()
	t.Logf("uname: %s", run("uname", "-a"))
	t.Logf("sw_vers: %s", run("sw_vers"))
	t.Logf("sandbox-exec: %v", exists("/usr/bin/sandbox-exec"))
	t.Logf("profiles: bsd.sb=%v system.sb=%v", exists("/usr/share/sandbox/bsd.sb"), exists("/System/Library/Sandbox/Profiles/system.sb"))
	t.Logf("otool -L self: %s", run("otool", "-L", exe))

	for _, r := range []struct {
		name string
		res  int
	}{{"RLIMIT_AS", syscall.RLIMIT_AS}, {"RLIMIT_DATA", syscall.RLIMIT_DATA}} {
		cmd := exec.Command(exe, "-test.run=^TestDarwinFacts$")
		cmd.Env = append(os.Environ(), "SPIKE_CHILD=alloc", fmt.Sprintf("SPIKE_RLIMIT=%d", r.res))
		out, err := cmd.CombinedOutput()
		t.Logf("%s set to 64MiB then alloc 256MiB: err=%v out=%s", r.name, err, trim(out))
	}
	{
		cmd := exec.Command(exe, "-test.run=^TestDarwinFacts$")
		cmd.Env = append(os.Environ(), "SPIKE_CHILD=spin")
		start := time.Now()
		out, err := cmd.CombinedOutput()
		t.Logf("RLIMIT_CPU=1 spin: err=%v after %v out=%s", err, time.Since(start).Round(time.Millisecond), trim(out))
	}

	tree := t.TempDir()
	payload := filepath.Join(tree, "payload")
	cp(t, exe, payload)
	rt := filepath.Join(tree, "rt")
	os.Mkdir(rt, 0o755)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	substrate := `(allow file-read* (subpath "/usr/lib") (subpath "/System/Library") (subpath "/System/Volumes/Preboot/Cryptexes") (subpath "/private/var/db/dyld") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (literal "/dev/zero"))`
	base := `(version 1)(deny default)(allow process-exec (subpath "` + tree + `"))(allow file-read* (subpath "` + tree + `"))`
	profiles := []struct{ name, sbpl string }{
		{"deny-default + exec + tree reads", base},
		{"+ substrate", base + substrate},
		{"+ sysctl + fork + metadata + mach", base + substrate + `(allow process-fork)(allow file-read-metadata)(allow sysctl-read)(allow mach-lookup)`},
		{"+ rt write + unix socket", base + substrate + `(allow process-fork)(allow file-read-metadata)(allow sysctl-read)(allow mach-lookup)(allow file-write* (subpath "` + rt + `"))(allow network* (local unix-socket) (remote unix-socket))`},
	}
	for _, p := range profiles {
		for _, mode := range []string{"hello", "readoutside", "writetree", "net", "sibling", "sock"} {
			cmd := exec.Command("/usr/bin/sandbox-exec", "-p", p.sbpl, payload, "-test.run=^TestDarwinFacts$")
			cmd.Env = []string{"SPIKE_CHILD=" + mode, "SPIKE_OUTSIDE=" + outside, "SPIKE_TREE=" + tree, "SPIKE_RT=" + rt, "HOME=/nonexistent"}
			out, err := cmd.CombinedOutput()
			t.Logf("[%s] %s: err=%v out=%s", p.name, mode, err, trim(out))
		}
	}
	t.Log("done")
}

func child() {
	switch os.Getenv("SPIKE_CHILD") {
	case "alloc":
		var res int
		fmt.Sscan(os.Getenv("SPIKE_RLIMIT"), &res)
		if err := syscall.Setrlimit(res, &syscall.Rlimit{Cur: 64 << 20, Max: 64 << 20}); err != nil {
			fmt.Println("setrlimit:", err)
			os.Exit(3)
		}
		b := make([]byte, 256<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		fmt.Println("allocated 256MiB fine")
	case "spin":
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 1, Max: 1}); err != nil {
			fmt.Println("setrlimit:", err)
			os.Exit(3)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
		}
		fmt.Println("spun 5s without being killed")
	case "hello":
		fmt.Println("hello from the sandbox")
	case "readoutside":
		_, err := os.ReadFile(os.Getenv("SPIKE_OUTSIDE"))
		fmt.Println("read outside:", err)
	case "writetree":
		err := os.WriteFile(filepath.Join(os.Getenv("SPIKE_TREE"), "w"), []byte("x"), 0o644)
		fmt.Println("write tree:", err)
	case "net":
		c, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
		if c != nil {
			c.Close()
		}
		fmt.Println("tcp dial:", err)
	case "sibling":
		sib := filepath.Join(os.Getenv("SPIKE_TREE"), "payload")
		cmd := exec.Command(sib, "-test.run=^TestDarwinFacts$")
		cmd.Env = []string{"SPIKE_CHILD=hello"}
		out, err := cmd.CombinedOutput()
		fmt.Printf("sibling exec: err=%v out=%s\n", err, strings.TrimSpace(string(out)))
	case "sock":
		p := filepath.Join(os.Getenv("SPIKE_RT"), "s")
		l, err := net.Listen("unix", p)
		if err != nil {
			fmt.Println("unix listen:", err)
			return
		}
		defer l.Close()
		go func() {
			c, _ := l.Accept()
			if c != nil {
				c.Close()
			}
		}()
		c, err := net.Dial("unix", p)
		if c != nil {
			c.Close()
		}
		fmt.Println("unix dial:", err)
	}
	os.Exit(0)
}

func run(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("(%v) %s", err, trim(out))
	}
	return trim(out)
}
func trim(b []byte) string {
	return strings.TrimSpace(string(bytes.ReplaceAll(b, []byte("\n"), []byte(" | "))))
}
func exists(p string) bool { _, err := os.Stat(p); return err == nil }
func cp(t *testing.T, from, to string) {
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o755); err != nil {
		t.Fatal(err)
	}
}
