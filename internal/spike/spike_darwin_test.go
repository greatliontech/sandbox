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
		cur  uint64
	}{{"RLIMIT_AS 64MiB", syscall.RLIMIT_AS, 64 << 20}, {"RLIMIT_AS 1GiB", syscall.RLIMIT_AS, 1 << 30}, {"RLIMIT_AS 8GiB", syscall.RLIMIT_AS, 8 << 30}, {"RLIMIT_DATA 1GiB", syscall.RLIMIT_DATA, 1 << 30}, {"RLIMIT_RSS(5) 64MiB", 5, 64 << 20}} {
		cmd := exec.Command(exe, "-test.run=^TestDarwinFacts$")
		cmd.Env = append(os.Environ(), "SPIKE_CHILD=alloc", fmt.Sprintf("SPIKE_RLIMIT=%d", r.res), fmt.Sprintf("SPIKE_CUR=%d", r.cur))
		out, err := cmd.CombinedOutput()
		t.Logf("%s then alloc 256MiB: err=%v out=%s", r.name, err, trim(out))
	}
	var lim syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_AS, &lim)
	t.Logf("RLIMIT_AS current: %+v", lim)
	syscall.Getrlimit(syscall.RLIMIT_DATA, &lim)
	t.Logf("RLIMIT_DATA current: %+v", lim)
	{
		start := time.Now()
		out, err := exec.Command("sh", "-c", "ulimit -t 1; yes > /dev/null; echo exit=$?").CombinedOutput()
		t.Logf("sh ulimit -t 1; yes: err=%v after %v out=%s", err, time.Since(start).Round(time.Millisecond), trim(out))
		start = time.Now()
		out, err = exec.Command("sh", "-c", "ulimit -S -t 1; ulimit -H -t 2; yes > /dev/null; echo exit=$?").CombinedOutput()
		t.Logf("sh soft 1 hard 2; yes: err=%v after %v out=%s", err, time.Since(start).Round(time.Millisecond), trim(out))
	}
	{
		cmd := exec.Command(exe, "-test.run=^TestDarwinFacts$")
		cmd.Env = append(os.Environ(), "SPIKE_CHILD=jetsam")
		out, err := cmd.CombinedOutput()
		t.Logf("memorystatus_control task limit 64MiB then alloc 256MiB: err=%v out=%s", err, trim(out))
	}

	tree, _ := filepath.EvalSymlinks(t.TempDir())
	payload := filepath.Join(tree, "payload")
	cp(t, exe, payload)
	rt := filepath.Join(tree, "rt")
	os.Mkdir(rt, 0o755)
	outsideDir, _ := filepath.EvalSymlinks(t.TempDir())
	outside := filepath.Join(outsideDir, "outside.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	t.Logf("tree=%s rt=%s outside=%s", tree, rt, outside)
	substrate := `(allow file-read* (subpath "/usr/lib") (subpath "/System/Library") (subpath "/System/Volumes/Preboot/Cryptexes") (subpath "/private/var/db/dyld") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (literal "/dev/zero"))`
	base := `(version 1)(deny default)(allow process-exec (subpath "` + tree + `"))(allow file-read* (subpath "` + tree + `"))`
	profiles := []struct{ name, sbpl string }{
		{"deny-default + exec + tree reads", base},
		{"+ substrate", base + substrate},
		{"+ sysctl + fork + metadata + mach", base + substrate + `(allow process-fork)(allow file-read-metadata)(allow sysctl-read)(allow mach-lookup)`},
		{"+ rt write + unix socket", base + substrate + `(allow process-fork)(allow file-read-metadata)(allow sysctl-read)(allow mach-lookup)(allow file-write* (subpath "` + rt + `"))(allow network* (local unix-socket) (remote unix-socket))`},
		{"system.sb import + tree", `(version 1)(deny default)(import "system.sb")(allow process-exec (subpath "` + tree + `"))(allow file-read* (subpath "` + tree + `"))(allow process-fork)(allow file-write* (subpath "` + rt + `"))(allow network* (local unix-socket) (remote unix-socket))`},
		{"allow default, deny net+write", `(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (subpath "` + rt + `"))`},
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
	case "jetsam":
		// memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT=6, pid, limitMB, 0, 0)
		_, _, errno := syscall.Syscall6(440, 6, uintptr(os.Getpid()), 64, 0, 0, 0)
		fmt.Println("memorystatus_control errno:", errno)
		b := make([]byte, 256<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		fmt.Println("allocated 256MiB fine under task limit")
	case "alloc":
		var res int
		var cur uint64
		fmt.Sscan(os.Getenv("SPIKE_RLIMIT"), &res)
		fmt.Sscan(os.Getenv("SPIKE_CUR"), &cur)
		var before syscall.Rlimit
		syscall.Getrlimit(res, &before)
		if err := syscall.Setrlimit(res, &syscall.Rlimit{Cur: cur, Max: before.Max}); err != nil {
			fmt.Printf("setrlimit (before %+v): %v\n", before, err)
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
