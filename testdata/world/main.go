//go:build ignore

// Command world is the Strong-world probe the live tests exec inside a
// sandboxed tree: it reports what the process can see and touch, one
// "key=value" line per fact, so each contract clause has one line to
// assert on. Arguments: the read-only grant, the read-write grant, and
// the rendezvous directory to probe (each may be empty).
package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	// Behavior modes for the bounds tests, selected by the first
	// argument; everything else reports facts.
	switch arg(1) {
	case "hog":
		// Announce, then touch 256 MiB: under a smaller memory bound
		// this dies after announcing — a bound that refused the process
		// its start leaves no announcement.
		fmt.Println("hog-start")
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
		return
	case "spawn":
		// Start a long sleeper, name it, and sleep alongside it: the
		// cancellation tests check the kill reaches both.
		p, err := os.StartProcess(os.Args[0], []string{os.Args[0], "sleep"}, &os.ProcAttr{})
		if err != nil {
			fmt.Printf("spawn-err=%v\n", err)
			return
		}
		fmt.Printf("child=%d\n", p.Pid)
		os.Stdout.Sync()
		time.Sleep(5 * time.Minute)
		return
	case "fork":
		// Start four idle copies; report how many the process bound
		// refused. os.Args[0] is this binary wherever the row execed
		// it.
		refused := 0
		var procs []*os.Process
		for i := 0; i < 4; i++ {
			p, err := os.StartProcess(os.Args[0], []string{os.Args[0], "idle"}, &os.ProcAttr{})
			if err != nil {
				refused++
				continue
			}
			procs = append(procs, p)
		}
		for _, p := range procs {
			p.Wait()
		}
		fmt.Printf("fork-refused=%d\n", refused)
		return
	case "idle":
		time.Sleep(200 * time.Millisecond)
		return
	case "sleep":
		time.Sleep(5 * time.Minute)
		return
	}
	ro, rw, run := arg(1), arg(2), arg(3)

	cwd, _ := os.Getwd()
	fmt.Println("cwd=" + cwd)
	fmt.Printf("pid=%d\n", os.Getpid())
	fmt.Printf("env=%d\n", len(os.Environ()))

	entries, _ := os.ReadDir("/")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	fmt.Println("root=" + strings.Join(names, ","))

	host, _ := os.ReadFile("/proc/sys/kernel/hostname")
	fmt.Printf("proc-hostname=%q\n", strings.TrimSpace(string(host)))

	fmt.Printf("write-root-err=%v\n", os.WriteFile("/probe", []byte("x"), 0o644) != nil)
	fmt.Printf("mkdir-root-err=%v\n", os.Mkdir("/probe-dir", 0o755) != nil)

	if ro != "" {
		b, err := os.ReadFile(ro + "/marker")
		fmt.Printf("ro-read=%q\n", string(b))
		fmt.Printf("ro-read-err=%v\n", err != nil)
		fmt.Printf("ro-write-err=%v\n", os.WriteFile(ro+"/probe", []byte("x"), 0o644) != nil)
	}
	if rw != "" {
		fmt.Printf("rw-write-err=%v\n", os.WriteFile(rw+"/probe", []byte("x"), 0o644) != nil)
	}
	if run != "" {
		fmt.Printf("run-write-err=%v\n", os.WriteFile(run+"/sock", []byte("x"), 0o644) != nil)
	}

	// Hardening facts: the capability sets, the bounding set, the
	// no_new_privs bit, and the filter's verdict on syscalls the Strong
	// row denies.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		fmt.Printf("caps=err:%v\n", err)
	} else {
		fmt.Printf("caps=e%x/%x,p%x/%x,i%x/%x\n", data[0].Effective, data[1].Effective, data[0].Permitted, data[1].Permitted, data[0].Inheritable, data[1].Inheritable)
	}
	bounding := 0
	for c := 0; c < 64; c++ {
		v, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil {
			break
		}
		if v != 0 {
			bounding++
		}
	}
	fmt.Printf("bounding=%d\n", bounding)
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	fmt.Printf("nnp=%d err=%v\n", nnp, err != nil)
	fmt.Printf("sethostname=%v\n", errno(unix.Sethostname([]byte("x"))))
	// A user namespace is the one namespace an unprivileged process
	// may always create, and a keyring lookup needs no capability: both
	// are refused only by the filter, so they tell the filter's arm
	// apart from the capability drop's.
	fmt.Printf("unshare=%v\n", errno(unix.Unshare(unix.CLONE_NEWUSER)))
	_, keyErr := unix.KeyctlInt(unix.KEYCTL_GET_KEYRING_ID, unix.KEY_SPEC_THREAD_KEYRING, 0, 0, 0)
	fmt.Printf("keyctl=%v\n", errno(keyErr))
	fmt.Printf("mount=%v\n", errno(unix.Mount("none", "/", "", unix.MS_REMOUNT|unix.MS_BIND, "")))
	fmt.Printf("ptrace=%v\n", errno(unix.PtraceAttach(1)))
	// Witnesses no capability governs: only the filter refuses these.
	_, _, uringErr := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, 0, 0)
	fmt.Printf("io_uring_setup=%v\n", errno(uringErr))
	_, _, perfErr := unix.Syscall6(unix.SYS_PERF_EVENT_OPEN, 0, 0, ^uintptr(0), ^uintptr(0), 0, 0)
	fmt.Printf("perf_event_open=%v\n", errno(perfErr))
	buf := make([]byte, 1)
	local := []unix.Iovec{{Base: &buf[0], Len: 1}}
	remote := []unix.RemoteIovec{{Base: uintptr(unsafe.Pointer(&buf[0])), Len: 1}}
	_, vmErr := unix.ProcessVMReadv(os.Getpid(), local, remote, 0)
	fmt.Printf("process_vm_readv=%v\n", errno(vmErr))
	_, _, keyReqErr := unix.Syscall6(unix.SYS_REQUEST_KEY, 0, 0, 0, 0, 0, 0)
	fmt.Printf("request_key=%v\n", errno(keyReqErr))
	var tx unix.Timex
	_, adjErr := unix.ClockAdjtime(unix.CLOCK_REALTIME, &tx)
	fmt.Printf("clock_adjtime=%v\n", errno(adjErr))
	_, dialErr := net.DialTimeout("tcp", "1.1.1.1:443", 2*time.Second)
	fmt.Printf("dial-err=%v\n", dialErr != nil)

	ifaces, _ := net.Interfaces()
	var ifnames []string
	for _, i := range ifaces {
		ifnames = append(ifnames, i.Name)
	}
	sort.Strings(ifnames)
	fmt.Println("ifaces=" + strings.Join(ifnames, ","))
}

// errno names a syscall's failure the way the row's filter produces
// it, so a test can tell EPERM from any other refusal.
func errno(err error) string {
	if err == nil {
		return "ok"
	}
	if e, ok := err.(syscall.Errno); ok {
		if e == 0 {
			return "ok"
		}
		return e.Error()
	}
	return err.Error()
}

func arg(i int) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return ""
}
