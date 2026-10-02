//go:build windows

// Command winspike asks a windows host the facts the windows row is
// built on: whether an unprivileged user can make an AppContainer
// profile, run a child under it with the host paths it is granted,
// what the child can and cannot reach, and what a Job Object bounds
// and reports. Every answer is a key=value line.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	userenv                           = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile     = userenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile     = userenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSidFromName = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

const (
	procThreadAttributeSecurityCapabilities = 0x00020009
	tokenIsAppContainer                     = 29
	jobObjectAssociateCompletionPort        = 7
)

type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

type jobAssociateCompletionPort struct {
	CompletionKey  uintptr
	CompletionPort windows.Handle
}

type jobBasicAccounting struct {
	TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
}

func main() {
	if len(os.Args) > 1 {
		child(os.Args[1], os.Args[2:])
		return
	}
	parent()
}

func fact(k string, v any) { fmt.Printf("%s=%v\n", k, v) }

func parent() {
	fact("goos", runtime.GOOS+"/"+runtime.GOARCH)
	exe, err := os.Executable()
	if err != nil {
		fact("exe", err)
		return
	}
	tree, err := os.MkdirTemp("", "spike-tree-")
	if err != nil {
		fact("tree", err)
		return
	}
	defer os.RemoveAll(tree)
	fact("tree", tree)
	payload := filepath.Join(tree, "payload.exe")
	if err := copyFile(exe, payload); err != nil {
		fact("copy", err)
		return
	}
	for _, d := range []string{"ro", "rw"} {
		os.Mkdir(filepath.Join(tree, d), 0o755)
	}
	os.WriteFile(filepath.Join(tree, "ro", "f"), []byte("x"), 0o644)

	// The profile: a per-user AppContainer, its SID.
	name := "sandbox-spike-" + strconv.Itoa(os.Getpid())
	sid, err := createProfile(name)
	if err != nil {
		fact("profile", err)
		return
	}
	defer deleteProfile(name)
	fact("profile", "ok")
	fact("sid", sid.String())

	// The grants: the tree read and executed, rw written too.
	if err := grant(tree, sid, windows.GENERIC_READ|windows.GENERIC_EXECUTE); err != nil {
		fact("grant-tree", err)
		return
	}
	fact("grant-tree", "ok")
	if err := grant(filepath.Join(tree, "rw"), sid, windows.GENERIC_ALL); err != nil {
		fact("grant-rw", err)
	}

	// A listener outside for the network probe.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ""
	if l != nil {
		addr = l.Addr().String()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}

	// An un-granted copy: the container cannot run what it cannot read.
	other, _ := os.MkdirTemp("", "spike-other-")
	defer os.RemoveAll(other)
	copyFile(exe, filepath.Join(other, "payload.exe"))
	if _, _, _, err := run(filepath.Join(other, "payload.exe"), sid, nil, []string{"probe", tree}, 5*time.Second); err != nil {
		fact("ungranted-run", err)
	} else {
		fact("ungranted-run", "ran")
	}
	fact("icacls-temp", icacls(filepath.Dir(tree)))
	fact("icacls-other", icacls(other))
	fact("icacls-tree", icacls(tree))

	// A directory whose descriptor the caller may not write: the grant fails.
	locked, _ := os.MkdirTemp("", "spike-locked-")
	defer func() {
		exec.Command("icacls", locked, "/grant", os.Getenv("USERNAME")+":(F)").Run()
		os.RemoveAll(locked)
	}()
	if out, err := exec.Command("icacls", locked, "/deny", os.Getenv("USERNAME")+":(WDAC)").CombinedOutput(); err != nil {
		fact("lock", fmt.Sprintf("%v %s", err, out))
	}
	fact("grant-locked", grant(locked, sid, windows.GENERIC_READ))

	// A sibling of the tree, granted: the payload may execute it.
	sibling, _ := os.MkdirTemp("", "spike-sibling-")
	defer os.RemoveAll(sibling)
	copyFile(exe, filepath.Join(sibling, "payload.exe"))
	fact("grant-sibling", grant(sibling, sid, windows.GENERIC_READ|windows.GENERIC_EXECUTE))
	// A library beside the payload, and one in an un-granted place.
	copyFile(`C:\Windows\System32\winmm.dll`, filepath.Join(tree, "sibling.dll"))
	copyFile(`C:\Windows\System32\winmm.dll`, filepath.Join(other, "sibling.dll"))

	// The kill tie: a sleeper in a job dies when the job's last handle closes.
	fact("kill-on-close", killOnClose(payload, sid))

	// The least environment a container launch needs.
	for name, vars := range map[string][]string{
		"none":                {},
		"systemroot":          {"SystemRoot=" + os.Getenv("SystemRoot")},
		"userprofile":         {"USERPROFILE=" + os.Getenv("USERPROFILE")},
		"localappdata":        {"LOCALAPPDATA=" + os.Getenv("LOCALAPPDATA")},
		"systemroot-profile":  {"SystemRoot=" + os.Getenv("SystemRoot"), "USERPROFILE=" + os.Getenv("USERPROFILE")},
		"systemroot-localapp": {"SystemRoot=" + os.Getenv("SystemRoot"), "LOCALAPPDATA=" + os.Getenv("LOCALAPPDATA")},
		"one-foreign":         {"SANDBOX_X=1"},
	} {
		childEnv = vars
		out, code, _, err := run(payload, sid, nil, []string{"envempty"}, 10*time.Second)
		childEnv = nil
		fact("env-"+name, fmt.Sprintf("err=%v exit=%d out=%s", err, code, strings.ReplaceAll(strings.TrimSpace(out), "\n", " ")))
	}

	for _, mode := range []string{"probe", "dll", "exec-sibling", "net", "hog", "jobhog", "jobhog-kill", "spin", "proctime", "spawn"} {
		limits := &windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		switch mode {
		case "hog":
			limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
			limits.ProcessMemoryLimit = 128 << 20
		case "jobhog", "jobhog-kill":
			limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
			limits.JobMemoryLimit = 128 << 20
		case "proctime":
			limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_TIME
			limits.BasicLimitInformation.PerProcessUserTimeLimit = 2 * 10_000_000
		case "spin":
			limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_TIME
			limits.BasicLimitInformation.PerJobUserTimeLimit = 2 * 10_000_000 // 100ns units: two seconds
		case "spawn":
			limits.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
			limits.BasicLimitInformation.ActiveProcessLimit = 3
		}
		args := []string{mode, tree, addr, sibling, other}
		switch mode {
		case "jobhog", "jobhog-kill":
			args[0] = "hog"
		case "proctime":
			args[0] = "spin"
		}
		killOnMemory = mode == "jobhog-kill"
		out, code, acct, err := run(payload, sid, limits, args, 15*time.Second)
		fact(mode+"-err", err)
		fact(mode+"-exit", code)
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line != "" {
				fact(mode+"-child-"+strings.SplitN(line, "=", 2)[0], strings.SplitN(line+"=", "=", 2)[1])
			}
		}
		fact(mode+"-acct", acct)
	}
}

// killOnMemory terminates the job on its memory limit's message.
var killOnMemory bool

// childEnv is the next child's environment block, nil for the
// parent's own.
var childEnv []string

func envBlock(vars []string) *uint16 {
	var block []uint16
	for _, v := range vars {
		u, _ := windows.UTF16FromString(v)
		block = append(block, u...)
	}
	block = append(block, 0)
	if len(vars) == 0 {
		block = append(block, 0)
	}
	return &block[0]
}

func icacls(path string) string {
	out, _ := exec.Command("icacls", path).CombinedOutput()
	return strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " | ")
}

// killOnClose starts a sleeper in a job with KILL_ON_JOB_CLOSE, closes
// the job's only handle and reports whether the sleeper died.
func killOnClose(exe string, sid *windows.SID) string {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err.Error()
	}
	limits := &windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(limits)), uint32(unsafe.Sizeof(*limits)))
	pi, err := start(exe, sid, []string{"sleep"}, 0, 0)
	if err != nil {
		return err.Error()
	}
	windows.AssignProcessToJobObject(job, pi.Process)
	windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(job)
	ev, _ := windows.WaitForSingleObject(pi.Process, 3000)
	var code uint32
	windows.GetExitCodeProcess(pi.Process, &code)
	windows.CloseHandle(pi.Process)
	if ev == uint32(windows.WAIT_TIMEOUT) {
		return "the sleeper outlived the job's handle"
	}
	return fmt.Sprintf("died, exit %d", code)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func createProfile(name string) (*windows.SID, error) {
	n, _ := windows.UTF16PtrFromString(name)
	var sid *windows.SID
	r, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if hr := int32(r); hr != 0 {
		if uint32(hr) == 0x800700B7 { // ERROR_ALREADY_EXISTS
			r, _, _ := procDeriveAppContainerSidFromName.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid)))
			if int32(r) != 0 {
				return nil, fmt.Errorf("derive: hresult %#x", uint32(r))
			}
			return sid, nil
		}
		return nil, fmt.Errorf("create: hresult %#x", uint32(hr))
	}
	return sid, nil
}

func deleteProfile(name string) {
	n, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(n)))
	fact("delete-profile", fmt.Sprintf("hresult %#x", uint32(r)))
}

// grant adds an allowing, inheriting ACE for sid on path.
func grant(path string, sid *windows.SID, access windows.ACCESS_MASK) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("dacl: %w", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, old)
	if err != nil {
		return fmt.Errorf("entries: %w", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// run starts exe under the container sid, in a job with the limits
// where given, its stdout captured; it returns the output, the exit
// code, the job's account and any failure to start.
// start creates exe suspended under the container sid, its stdout
// and stderr the handle out where given.
func start(exe string, sid *windows.SID, args []string, out windows.Handle, _ int) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return pi, fmt.Errorf("attribute list: %w", err)
	}
	defer al.Delete()
	caps := securityCapabilities{AppContainerSid: sid}
	if err := al.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
		return pi, fmt.Errorf("capabilities attribute: %w", err)
	}
	si := &windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(*si))
	if out != 0 {
		si.Flags = windows.STARTF_USESTDHANDLES
		si.StdOutput = out
		si.StdErr = out
	}
	si.ProcThreadAttributeList = al.List()
	cmdline := syscall.EscapeArg(exe)
	for _, a := range args {
		cmdline += " " + syscall.EscapeArg(a)
	}
	exeP, _ := windows.UTF16PtrFromString(exe)
	cmdP, _ := windows.UTF16PtrFromString(cmdline)
	flags := uint32(windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT)
	var env *uint16
	if childEnv != nil {
		env = envBlock(childEnv)
	}
	err = windows.CreateProcess(exeP, cmdP, nil, nil, out != 0, flags, env, nil, &si.StartupInfo, &pi)
	if err != nil {
		return pi, fmt.Errorf("create process: %w", err)
	}
	return pi, nil
}

func run(exe string, sid *windows.SID, limits *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION, args []string, wait time.Duration) (string, uint32, string, error) {
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	var r, w windows.Handle
	if err := windows.CreatePipe(&r, &w, sa, 0); err != nil {
		return "", 0, "", fmt.Errorf("pipe: %w", err)
	}
	windows.SetHandleInformation(r, windows.HANDLE_FLAG_INHERIT, 0)
	pi, err := start(exe, sid, args, w, 0)
	windows.CloseHandle(w)
	if err != nil {
		windows.CloseHandle(r)
		return "", 0, "", err
	}
	var job, port windows.Handle
	acct := ""
	if limits != nil {
		job, err = windows.CreateJobObject(nil, nil)
		if err != nil {
			return "", 0, "", fmt.Errorf("job: %w", err)
		}
		defer windows.CloseHandle(job)
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(limits)), uint32(unsafe.Sizeof(*limits))); err != nil {
			return "", 0, "", fmt.Errorf("job limits: %w", err)
		}
		port, err = windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
		if err == nil {
			assoc := jobAssociateCompletionPort{CompletionKey: 1, CompletionPort: port}
			if _, err := windows.SetInformationJobObject(job, jobObjectAssociateCompletionPort, uintptr(unsafe.Pointer(&assoc)), uint32(unsafe.Sizeof(assoc))); err != nil {
				acct += fmt.Sprintf("port-assoc:%v ", err)
			}
		}
		if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
			return "", 0, "", fmt.Errorf("assign: %w", err)
		}
	}
	started := time.Now()
	if killOnMemory && port != 0 {
		go func() {
			for {
				var qty uint32
				var key uintptr
				var ov *windows.Overlapped
				if err := windows.GetQueuedCompletionStatus(port, &qty, &key, &ov, 20000); err != nil {
					return
				}
				if qty == 10 {
					windows.TerminateJobObject(job, 137)
					fmt.Printf("memory-kill-after=%v\n", time.Since(started))
					return
				}
			}
		}()
	}
	windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread)
	outDone := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(os.NewFile(uintptr(r), "pipe"))
		outDone <- string(b)
	}()
	ev, _ := windows.WaitForSingleObject(pi.Process, uint32(wait/time.Millisecond))
	if ev == uint32(windows.WAIT_TIMEOUT) {
		windows.TerminateProcess(pi.Process, 99)
		windows.WaitForSingleObject(pi.Process, 5000)
		acct += "timed-out "
	}
	var code uint32
	windows.GetExitCodeProcess(pi.Process, &code)
	windows.CloseHandle(pi.Process)
	out := <-outDone
	if limits != nil {
		var a jobBasicAccounting
		var n uint32
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&a)), uint32(unsafe.Sizeof(a)), &n); err == nil {
			acct += fmt.Sprintf("user=%v kernel=%v procs=%d active=%d ", time.Duration(a.TotalUserTime*100), time.Duration(a.TotalKernelTime*100), a.TotalProcesses, a.ActiveProcesses)
		} else {
			acct += fmt.Sprintf("acct-err:%v ", err)
		}
		var x windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		if err := windows.QueryInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&x)), uint32(unsafe.Sizeof(x)), &n); err == nil {
			acct += fmt.Sprintf("peak-proc=%d peak-job=%d ", x.PeakProcessMemoryUsed, x.PeakJobMemoryUsed)
		}
		if port != 0 {
			for {
				var qty uint32
				var key uintptr
				var ov *windows.Overlapped
				if err := windows.GetQueuedCompletionStatus(port, &qty, &key, &ov, 0); err != nil {
					break
				}
				acct += fmt.Sprintf("msg=%d:%d ", qty, uintptr(unsafe.Pointer(ov)))
			}
			windows.CloseHandle(port)
		}
	}
	return out, code, acct, nil
}

func child(mode string, args []string) {
	switch mode {
	case "probe":
		tree := args[0]
		fact("appcontainer", tokenDword(tokenIsAppContainer))
		fact("integrity", integrity())
		_, err := os.ReadFile(filepath.Join(tree, "ro", "f"))
		fact("read-ro", err)
		_, err = os.ReadFile(`C:\Windows\System32\kernel32.dll`)
		fact("read-system", err)
		home, _ := os.UserHomeDir()
		_, err = os.ReadDir(home)
		fact("read-home", err)
		_, err = os.ReadDir(`C:\`)
		fact("read-root", err)
		err = os.WriteFile(filepath.Join(tree, "ro", "w"), []byte("x"), 0o644)
		fact("write-ro", err)
		err = os.WriteFile(filepath.Join(tree, "rw", "w"), []byte("x"), 0o644)
		fact("write-rw", err)
		err = os.WriteFile(filepath.Join(os.TempDir(), "spike-w"), []byte("x"), 0o644)
		fact("write-temp", err)
		fact("temp", os.TempDir())
		fact("localappdata", os.Getenv("LOCALAPPDATA"))
		fact("env", len(os.Environ()))
	case "envempty":
		fact("ran", "yes")
		fact("env", len(os.Environ()))
		fact("temp", os.TempDir())
		fact("systemroot", os.Getenv("SystemRoot"))
		_, err := os.ReadFile(`C:\Windows\System32\kernel32.dll`)
		fact("read-system", err)
	case "dll":
		tree := args[0]
		d, err := windows.LoadDLL(filepath.Join(tree, "sibling.dll"))
		if d != nil {
			d.Release()
		}
		fact("load-granted", err)
		d, err = windows.LoadDLL(filepath.Join(args[3], "sibling.dll"))
		if d != nil {
			d.Release()
		}
		fact("load-ungranted", err)
	case "exec-sibling":
		files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
		p, err := os.StartProcess(filepath.Join(args[2], "payload.exe"), []string{"payload.exe", "ran"}, &os.ProcAttr{Files: files})
		if err == nil {
			p.Wait()
		}
		fact("exec-sibling", err)
		p, err = os.StartProcess(filepath.Join(args[3], "payload.exe"), []string{"payload.exe", "ran"}, &os.ProcAttr{Files: files})
		if err == nil {
			p.Wait()
		}
		fact("exec-ungranted", err)
	case "ran":
		fact("sibling-ran", "yes")
	case "net":
		c, err := net.DialTimeout("tcp", args[1], 3*time.Second)
		if c != nil {
			c.Close()
		}
		fact("dial", err)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if l != nil {
			l.Close()
		}
		fact("listen", err)
	case "hog":
		fact("hog", "start")
		bufs := make([][]byte, 0)
		for i := 0; i < 8; i++ {
			b := make([]byte, 64<<20)
			for j := range b {
				b[j] = byte(j)
			}
			bufs = append(bufs, b)
			fact("held", (i+1)*64)
		}
		fact("hogged", "yes")
	case "spin":
		fact("spin", "start")
		end := time.Now().Add(10 * time.Second)
		x := 0
		for time.Now().Before(end) {
			x++
		}
		fact("spun", "yes")
	case "spawn":
		exe, _ := os.Executable()
		for i := 1; i <= 3; i++ {
			p, err := os.StartProcess(exe, []string{exe, "sleep"}, &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
			if err != nil {
				fact("spawn-"+strconv.Itoa(i), err)
				continue
			}
			fact("spawn-"+strconv.Itoa(i), "ok")
			defer p.Kill()
		}
	case "sleep":
		time.Sleep(5 * time.Second)
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

func integrity() string {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); err != nil {
		return err.Error()
	}
	defer t.Close()
	var n uint32
	windows.GetTokenInformation(t, windows.TokenIntegrityLevel, nil, 0, &n)
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return err.Error()
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	return label.Label.Sid.String()
}
