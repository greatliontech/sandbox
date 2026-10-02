//go:build darwin

package spike

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestDarwinFacts2(t *testing.T) {
	if os.Getenv("SPIKE_CHILD") != "" {
		child()
		return
	}
	if b, err := os.ReadFile("/System/Library/Sandbox/Profiles/system.sb"); err == nil {
		t.Logf("system.sb (%d bytes):\n%s", len(b), b)
	} else {
		t.Logf("system.sb unreadable: %v", err)
	}
	exe, _ := os.Executable()
	tree, _ := filepath.EvalSymlinks(t.TempDir())
	payload := filepath.Join(tree, "payload")
	cp(t, exe, payload)
	rt := filepath.Join(tree, "rt")
	os.Mkdir(rt, 0o755)
	outsideDir, _ := filepath.EvalSymlinks(t.TempDir())
	// A socket outside the runtime dir, listened by the parent.
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
	base := `(version 1)(deny default)(import "system.sb")(allow process-exec (subpath "` + tree + `"))(allow process-fork)(allow file-read* (subpath "` + tree + `"))(allow file-write* (subpath "` + rt + `"))`
	profiles := []struct{ name, sbpl string }{
		{"unix any", base + `(allow network* (local unix-socket) (remote unix-socket))`},
		{"unix outbound subpath rt", base + `(allow network-outbound (remote unix-socket (subpath "` + rt + `")))(allow network-inbound (local unix-socket (subpath "` + rt + `")))(allow network-bind (local unix-socket (subpath "` + rt + `")))`},
		{"unix outbound path-literal", base + `(allow network-outbound (remote unix-socket (path-literal "` + rt + `/s")))`},
		{"network granted", base + `(allow network*)`},
		{"no socket rules", base},
	}
	for _, p := range profiles {
		for _, mode := range []string{"sock", "sockout", "net", "execout", "readetc"} {
			cmd := exec.Command("/usr/bin/sandbox-exec", "-p", p.sbpl, payload, "-test.run=^TestDarwinFacts2$")
			cmd.Env = []string{"SPIKE_CHILD=" + mode, "SPIKE_TREE=" + tree, "SPIKE_RT=" + rt, "SPIKE_OUTSOCK=" + outSock, "HOME=/nonexistent"}
			out, err := cmd.CombinedOutput()
			t.Logf("[%s] %s: err=%v out=%s", p.name, mode, err, trim(out))
			os.Remove(filepath.Join(rt, "s"))
		}
	}
	// proc_info readings of a child: resident size and CPU time via
	// __proc_info(2, pid, PROC_PIDTASKINFO=4, 0, buf, len).
	hog := exec.Command(exe, "-test.run=^TestDarwinFacts2$")
	hog.Env = append(os.Environ(), "SPIKE_CHILD=hold")
	hog.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := hog.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	var ti [256]byte // struct proc_taskinfo is 96 bytes
	start := time.Now()
	n, _, errno := syscall.Syscall6(336, 2, uintptr(hog.Process.Pid), 4, 0, uintptr(unsafe.Pointer(&ti[0])), uintptr(len(ti)))
	t.Logf("proc_info PIDTASKINFO: n=%d errno=%v took %v", n, errno, time.Since(start))
	if errno == 0 {
		rss := *(*uint64)(unsafe.Pointer(&ti[8]))
		utime := *(*uint64)(unsafe.Pointer(&ti[16]))
		stime := *(*uint64)(unsafe.Pointer(&ti[24]))
		t.Logf("pti_resident_size=%d MiB utime=%dns stime=%dns", rss>>20, utime, stime)
	}
	// The process group's members via sysctl kern.proc.pgrp.<pgid>.
	raw, err := unix.SysctlRaw("kern.proc.pgrp", hog.Process.Pid)
	t.Logf("kern.proc.pgrp: %d bytes (kinfo_proc is 648 bytes: %d entries), err=%v", len(raw), len(raw)/648, err)
	// Sampling cost over 100 rounds.
	start = time.Now()
	for i := 0; i < 100; i++ {
		syscall.Syscall6(336, 2, uintptr(hog.Process.Pid), 4, 0, uintptr(unsafe.Pointer(&ti[0])), uintptr(len(ti)))
		unix.SysctlRaw("kern.proc.pgrp", hog.Process.Pid)
	}
	t.Logf("100 samples (proc_info + pgrp listing): %v", time.Since(start))
	syscall.Kill(-hog.Process.Pid, syscall.SIGKILL)
	hog.Wait()
	t.Log("done2")
}

func init() {
	if os.Getenv("SPIKE_CHILD") == "" {
		return
	}
	switch os.Getenv("SPIKE_CHILD") {
	case "hold":
		b := make([]byte, 100<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "sockout":
		c, err := net.Dial("unix", os.Getenv("SPIKE_OUTSOCK"))
		if c != nil {
			c.Close()
		}
		fmt.Println("unix dial outside:", err)
		os.Exit(0)
	case "execout":
		out, err := exec.Command("/bin/ls", "/").CombinedOutput()
		fmt.Printf("exec /bin/ls: err=%v out=%.40q\n", err, string(out))
		os.Exit(0)
	case "readetc":
		_, err1 := os.ReadFile("/etc/hosts")
		_, err2 := os.ReadFile("/usr/share/zoneinfo/UTC")
		_, err3 := os.ReadDir("/Users")
		fmt.Printf("read /etc/hosts: %v; /usr/share/zoneinfo/UTC: %v; readdir /Users: %v\n", err1, err2, err3)
		os.Exit(0)
	}
}
