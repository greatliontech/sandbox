//go:build windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsSandbox runs one payload under the row this host reaches:
// an AppContainer of the run's own on the OS row, with the host paths
// the run is granted — the entrypoint's own directory, each grant,
// the rendezvous directory — carrying an entry for the container's
// identity in their security descriptors for the run's duration; a
// Job Object on every row, every process of the run born into it,
// holding the bounds and the kill tie.
type windowsSandbox struct {
	spec    Spec
	row     row // the row that ran; meaningful once process is set
	process windows.Handle
	profile *profile
	held    []grantee // the entries carrying the container, not yet relieved
	bounds  *bounds
	copiers sync.WaitGroup
	closers []io.Closer

	mu      sync.Mutex // guards final and the run's end
	final   *Stats
	running bool
	outcome outcome // Wait's reaping memoized: Destroy waits too
}

func newSandbox(spec Spec) (Sandbox, error) {
	return &windowsSandbox{spec: spec}, nil
}

// selection is the row this host reaches and what it lacks for the
// rows above.
func selection(ctx context.Context) (row, []string, error) {
	facts, err := hostFactsFor(ctx)
	if err != nil {
		return row{}, nil, err
	}
	r, below := selectRow(facts)
	return r, below, nil
}

func reach(ctx context.Context, _ Spec) (Isolation, []string, error) {
	r, below, err := selection(ctx)
	if err != nil {
		return None, nil, err
	}
	return r.tier, below, nil
}

func (s *windowsSandbox) Tier() Isolation { return s.row.tier }

// world is the resolved shape of a run: the entrypoint and working
// directory as the process sees them, and the paths the container is
// granted with the access each carries.
type world struct {
	cmd     string
	workDir string
	grants  []grantee
}

// grantee is one host path the container is granted: read and
// executed, written too where read-write.
type grantee struct {
	path  string
	write bool
}

// resolveWorld checks, before anything runs, that every stated
// intent has somewhere to land on row r (docs/specs/sandbox.md,
// "Intent is portable; delivery is all-or-nothing"): the spelling
// checks, the row's own refusals, the entrypoint an executable file
// on the host, each grant and the rendezvous directory an entry on
// the host, no two of them one entry or one within another — judged
// by the entries' identities, never their spellings, which the
// platform folds and aliases (a case variant, a short name, a
// junction). On the OS row the world is what the container is
// granted: the entrypoint's own directory read and executed — the
// platform loads a program's libraries from beside it — each grant
// read and executed, and written where read-write, the rendezvous
// directory read and written; the platform grants every package the
// system's own files besides.
func resolveWorld(spec Spec, r row) (world, error) {
	undeliverable := func(format string, a ...any) (world, error) {
		return world{}, fmt.Errorf("%w: "+format, append([]any{ErrUndeliverable}, a...)...)
	}
	if !filepath.IsAbs(spec.Exec) {
		return undeliverable("exec %q is not an absolute path", spec.Exec)
	}
	if spec.WorkDir != "" && !filepath.IsAbs(spec.WorkDir) {
		return undeliverable("workdir %q is not an absolute path", spec.WorkDir)
	}
	if err := r.refuses(spec); err != nil {
		return world{}, err
	}
	fi, err := os.Stat(spec.Exec)
	if err != nil {
		return undeliverable("exec %s: %v", spec.Exec, err)
	}
	if fi.IsDir() {
		return undeliverable("exec %s: is a directory", spec.Exec)
	}
	w := world{cmd: spec.Exec, workDir: spec.WorkDir}
	if r.tier != OS {
		return w, nil
	}
	w.grants = append(w.grants, grantee{path: filepath.Dir(spec.Exec)})
	type stated struct {
		path, what string
		write      bool
	}
	var paths []stated
	for _, g := range spec.PathGrants {
		paths = append(paths, stated{g.Path, "grant", g.Access != ReadOnly})
	}
	if spec.RuntimeDir != "" {
		paths = append(paths, stated{spec.RuntimeDir, "runtime dir", true})
	}
	var lines []lineage
	for _, p := range paths {
		if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path {
			return undeliverable("%s %q is not a clean absolute path", p.what, p.path)
		}
		fi, err := os.Stat(p.path)
		if err != nil {
			return undeliverable("%s %s: %v", p.what, p.path, err)
		}
		if p.what == "runtime dir" && !fi.IsDir() {
			return undeliverable("runtime dir %s is not a directory", p.path)
		}
		l, err := lineageOf(p.path)
		if err != nil {
			return undeliverable("%s %s: %v", p.what, p.path, err)
		}
		for i, o := range lines {
			if l.same(o) || l.holds(o) || o.holds(l) {
				return undeliverable("grants %s and %s overlap", paths[i].path, p.path)
			}
		}
		lines = append(lines, l)
		w.grants = append(w.grants, grantee{path: p.path, write: p.write})
	}
	return w, nil
}

// identity is an entry's identity on the host: the volume's serial
// and the file's index on it, which every spelling of one entry
// shares — a case variant's, a short name's, a junction's.
type identity struct{ volume, index uint64 }

// lineage is the identities of an entry and of every directory above
// it, the entry's own first — above the entry where it stands, not
// where it was spelled: a junction's or symbolic link's spelling is
// resolved first (finalPath), so that a grant through one is judged
// against the directories over its target.
type lineage []identity

func lineageOf(path string) (lineage, error) {
	path, err := finalPath(path)
	if err != nil {
		return nil, err
	}
	var l lineage
	for {
		id, err := identityOf(path)
		if err != nil {
			return nil, err
		}
		l = append(l, id)
		parent := filepath.Dir(path)
		if parent == path {
			return l, nil
		}
		path = parent
	}
}

// finalPath is the path an entry stands at, every junction and
// symbolic link on the way resolved, as the kernel spells it.
func finalPath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
		}
		buf = make([]uint16, n+1)
	}
}

// identityOf reads an entry's identity through a handle opened for
// no access, a directory included (FILE_FLAG_BACKUP_SEMANTICS).
func identityOf(path string) (identity, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return identity{}, err
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return identity{}, err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return identity{}, err
	}
	return identity{volume: uint64(info.VolumeSerialNumber), index: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)}, nil
}

func (l lineage) same(o lineage) bool  { return l[0] == o[0] }
func (l lineage) holds(o lineage) bool { return slices.Contains(o[1:], l[0]) }

// Start selects the row this host's facts satisfy, refuses below
// MinTier before anything runs, resolves the world and the bounds,
// and creates the payload's process — suspended, placed in the Job,
// then released — under the container on the OS row. A context
// ended already refuses, as os/exec does: the wall clock is the
// caller's.
func (s *windowsSandbox) Start(ctx context.Context) error {
	if s.process != 0 {
		return errors.New("sandbox: already started")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r, below, err := selection(ctx)
	if err != nil {
		return err
	}
	if r.tier < s.spec.MinTier {
		return &TierError{Reached: r.tier, Required: s.spec.MinTier, Lacking: below}
	}
	w, err := resolveWorld(s.spec, r)
	if err != nil {
		return err
	}
	b, err := newBounds(s.spec.Limits)
	if err != nil {
		return err
	}
	// From here every failure path releases what the run holds.
	var p *profile
	var held []grantee
	fail := func(err error) error {
		for _, g := range held {
			_ = relieve(g.path, p.sid)
		}
		_ = p.delete()
		b.close()
		return err
	}
	var caps *securityCapabilities
	if r.tier == OS {
		if p, err = newProfile("run"); err != nil {
			return fail(fmt.Errorf("sandbox: appcontainer profile: %w", err))
		}
		for _, g := range w.grants {
			switch err := admit(g.path, p.sid, g.write); {
			case errors.Is(err, errReachedAlready):
			case err != nil:
				return fail(fmt.Errorf("%w: cannot grant %s to the container: %v", ErrUndeliverable, g.path, err))
			default:
				held = append(held, g)
			}
		}
		caps = &securityCapabilities{AppContainerSid: p.sid}
		if s.spec.Network {
			caps.Capabilities, caps.CapabilityCount, err = networkCapabilities()
			if err != nil {
				return fail(fmt.Errorf("sandbox: network capabilities: %w", err))
			}
		}
	}
	pi, closers, err := s.create(w, caps, containerEnv(s.spec, r))
	if err != nil {
		return fail(err)
	}
	// A process abandoned before it ran: ended and its streams closed;
	// the copiers end on their own as the pipes do (a stated reader
	// that never ends keeps its copier, as it would keep Wait).
	abandon := func(err error) error {
		windows.TerminateProcess(pi.Process, killExitCode)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		for _, c := range closers {
			c.Close()
		}
		return fail(err)
	}
	if err := b.assign(pi.Process); err != nil {
		return abandon(err)
	}
	b.start()
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		b.halt()
		return abandon(fmt.Errorf("sandbox: resume: %w", err))
	}
	windows.CloseHandle(pi.Thread)
	s.process, s.row, s.profile, s.held, s.bounds, s.closers = pi.Process, r, p, held, b, closers
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	// Cancellation kills the run through its Job, which no process
	// leaves; the kill is the bounds' own, which answers nothing once
	// the Job is closed.
	go func() {
		select {
		case <-ctx.Done():
			b.kill()
		case <-b.done:
		}
	}()
	return nil
}

// containerEnv is the payload's environment on this platform: the
// stated one, or the host's own without a Root — with the two
// variables the platform's own machinery reads, carried from the
// host where the stated environment lacks them: LOCALAPPDATA, which
// a container's launch demands and redirects to the package's own
// directory, adding the temporary directory's variables (TEMP, TMP)
// redirected there; and SystemRoot, from which the platform's own
// libraries resolve their paths (the network's providers among
// them).
func containerEnv(spec Spec, r row) []string {
	env := payloadEnv(spec)
	if r.tier != OS {
		return env
	}
	env = append([]string{}, env...)
	for _, name := range []string{"LOCALAPPDATA", "SystemRoot"} {
		if !hasVar(env, name) {
			env = append(env, name+"="+os.Getenv(name))
		}
	}
	return env
}

// hasVar reports whether env states the variable, the platform
// folding case.
func hasVar(env []string, name string) bool {
	for _, kv := range env {
		if len(kv) > len(name) && kv[len(name)] == '=' && strings.EqualFold(kv[:len(name)], name) {
			return true
		}
	}
	return false
}

// create makes the payload's process, suspended: the command line
// from the entrypoint and arguments, the environment block, the
// working directory, the standard streams as pipes copied from and
// to the spec's where they are not files of the host's own, and the
// container's capabilities where the row has them. The streams'
// handles are the only ones inherited.
func (s *windowsSandbox) create(w world, caps *securityCapabilities, env []string) (windows.ProcessInformation, []io.Closer, error) {
	var pi windows.ProcessInformation
	var closers []io.Closer
	closeAll := func() {
		for _, c := range closers {
			c.Close()
		}
	}
	si := &windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	var inherited []windows.Handle
	for i, stream := range []any{s.spec.Stdin, s.spec.Stdout, s.spec.Stderr} {
		h, c, err := s.stream(i, stream)
		if err != nil {
			closeAll()
			return pi, nil, err
		}
		closers = append(closers, c...)
		inherited = append(inherited, h)
		switch i {
		case 0:
			si.StdInput = h
		case 1:
			si.StdOutput = h
		case 2:
			si.StdErr = h
		}
	}
	attrs := uint32(1)
	if caps != nil {
		attrs++
	}
	al, err := windows.NewProcThreadAttributeList(attrs)
	if err != nil {
		closeAll()
		return pi, nil, fmt.Errorf("sandbox: attribute list: %w", err)
	}
	defer al.Delete()
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		closeAll()
		return pi, nil, fmt.Errorf("sandbox: handle list: %w", err)
	}
	if caps != nil {
		if err := al.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(caps), unsafe.Sizeof(*caps)); err != nil {
			closeAll()
			return pi, nil, fmt.Errorf("sandbox: security capabilities: %w", err)
		}
	}
	si.ProcThreadAttributeList = al.List()
	cmdline := syscall.EscapeArg(w.cmd)
	for _, a := range s.spec.Args {
		cmdline += " " + syscall.EscapeArg(a)
	}
	exeP, err := windows.UTF16PtrFromString(w.cmd)
	if err != nil {
		closeAll()
		return pi, nil, fmt.Errorf("sandbox: exec: %w", err)
	}
	cmdP, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		closeAll()
		return pi, nil, fmt.Errorf("sandbox: arguments: %w", err)
	}
	var dirP *uint16
	if w.workDir != "" {
		if dirP, err = windows.UTF16PtrFromString(w.workDir); err != nil {
			closeAll()
			return pi, nil, fmt.Errorf("sandbox: workdir: %w", err)
		}
	}
	block, err := envBlock(env)
	if err != nil {
		closeAll()
		return pi, nil, err
	}
	flags := uint32(windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT)
	if err := windows.CreateProcess(exeP, cmdP, nil, nil, true, flags, &block[0], dirP, &si.StartupInfo, &pi); err != nil {
		closeAll()
		return pi, nil, fmt.Errorf("%w: exec %s: %v", ErrUndeliverable, w.cmd, err)
	}
	// The payload holds its own copies of the streams' handles; ours
	// are closed, so that the copiers meet EOF when the run's last
	// writer goes.
	var kept []io.Closer
	for _, c := range closers {
		if hc, ok := c.(handleCloser); ok && slices.Contains(inherited, hc.h) {
			hc.Close()
			continue
		}
		kept = append(kept, c)
	}
	return pi, kept, nil
}

// handleCloser closes a raw handle.
type handleCloser struct{ h windows.Handle }

func (c handleCloser) Close() error { return windows.CloseHandle(c.h) }

// stream is the inheritable handle for one standard stream: a file
// of the host's own as it is (its handle made inheritable through a
// duplicate), a nil stream as the null device, and anything else as
// one end of a pipe whose other end a goroutine copies — the pipe
// made uninheritable and the payload's end duplicated inheritable,
// so that no end of ours is ever inheritable.
func (s *windowsSandbox) stream(i int, v any) (windows.Handle, []io.Closer, error) {
	inheritable := func(h windows.Handle) (windows.Handle, error) {
		var dup windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &dup, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return 0, fmt.Errorf("sandbox: stream %d: %w", i, err)
		}
		return dup, nil
	}
	if v == nil {
		mode := uint32(windows.GENERIC_READ)
		if i > 0 {
			mode = windows.GENERIC_WRITE
		}
		h, err := windows.CreateFile(windows.StringToUTF16Ptr("NUL"), mode, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			return 0, nil, fmt.Errorf("sandbox: null device: %w", err)
		}
		return h, []io.Closer{handleCloser{h}}, nil
	}
	if f, ok := v.(*os.File); ok {
		dup, err := inheritable(windows.Handle(f.Fd()))
		if err != nil {
			return 0, nil, err
		}
		return dup, []io.Closer{handleCloser{dup}}, nil
	}
	var r, w windows.Handle
	if err := windows.CreatePipe(&r, &w, nil, 0); err != nil {
		return 0, nil, fmt.Errorf("sandbox: stream %d: %w", i, err)
	}
	if i == 0 {
		theirs, err := inheritable(r)
		windows.CloseHandle(r)
		if err != nil {
			windows.CloseHandle(w)
			return 0, nil, err
		}
		wf := os.NewFile(uintptr(w), "stdin")
		s.copiers.Add(1)
		go func() {
			defer s.copiers.Done()
			io.Copy(wf, v.(io.Reader))
			wf.Close()
		}()
		return theirs, []io.Closer{handleCloser{theirs}, wf}, nil
	}
	theirs, err := inheritable(w)
	windows.CloseHandle(w)
	if err != nil {
		windows.CloseHandle(r)
		return 0, nil, err
	}
	rf := os.NewFile(uintptr(r), "stdout")
	s.copiers.Add(1)
	go func() {
		defer s.copiers.Done()
		io.Copy(v.(io.Writer), rf)
		rf.Close()
	}()
	return theirs, []io.Closer{handleCloser{theirs}}, nil
}

// envBlock spells an environment as the platform wants it: each
// entry NUL-terminated, the block twice so, never empty.
func envBlock(env []string) ([]uint16, error) {
	var block []uint16
	for _, kv := range env {
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, fmt.Errorf("sandbox: environment entry %q: %w", kv, err)
		}
		block = append(block, u...)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}

// Wait reaps the payload and reports how it ended: its exit code,
// never a signal, the platform having none — a process the sandbox
// ended exits with killExitCode. At the payload's exit the run's
// remnants are ended through the Job, the Job's readers halted and
// its account read, the Job closed, the container's profile deleted
// and the granted entries relieved of its identity. A bound the
// watchdog could not hold is Wait's error. Wait is memoized: Destroy
// waits too, a later call returns the first's outcome, and a release
// that failed is retried by it.
func (s *windowsSandbox) Wait() (ExitStatus, error) {
	if s.process == 0 {
		return ExitStatus{}, errors.New("sandbox: not started")
	}
	if !s.outcome.begin() {
		status, err := s.outcome.result()
		if rerr := s.outcome.release(s.release); rerr != nil {
			return status, errors.Join(err, rerr)
		}
		return status, err
	}
	var waitErr error
	ev, err := windows.WaitForSingleObject(s.process, windows.INFINITE)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		waitErr = fmt.Errorf("sandbox: wait: %v (%d)", err, ev)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(s.process, &code); err != nil && waitErr == nil {
		waitErr = fmt.Errorf("sandbox: exit code: %w", err)
	}
	status := ExitStatus{Code: int(code)}
	// The run's remnants end with the payload, before the port is
	// drained: a descendant left running would keep it busy.
	s.bounds.finish()
	s.bounds.halt()
	st, serr := s.bounds.stats()
	if serr != nil && waitErr == nil {
		waitErr = serr
	}
	s.bounds.close()
	for _, c := range s.closers {
		c.Close()
	}
	s.copiers.Wait()
	// The handle is closed only once no Signal can reach it.
	s.mu.Lock()
	s.final, s.running = &st, false
	windows.CloseHandle(s.process)
	s.mu.Unlock()
	s.outcome.end(status, waitErr)
	if rerr := s.outcome.release(s.release); rerr != nil {
		return status, errors.Join(waitErr, rerr)
	}
	return status, waitErr
}

// release relieves the granted entries of the container and deletes
// its profile, once each; what failed stays for a later try.
func (s *windowsSandbox) release() error {
	var errs []error
	var left []grantee
	for _, g := range s.held {
		if err := relieve(g.path, s.profile.sid); err != nil {
			errs = append(errs, fmt.Errorf("sandbox: relieving %s of the container: %w", g.path, err))
			left = append(left, g)
		}
	}
	s.held = left
	if len(left) == 0 {
		if err := s.profile.delete(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Signal ends the payload: the platform has no signals, so only
// os.Kill is delivered, as a termination of the payload's process
// alone (the Job's kill, which ends the run whole, is cancellation's
// and Destroy's); a run already ended has nothing to end.
func (s *windowsSandbox) Signal(sig os.Signal) error {
	if s.process == 0 {
		return errors.New("sandbox: not started")
	}
	if sig != os.Kill {
		return fmt.Errorf("%w: this platform delivers no signal but os.Kill", ErrUndeliverable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return errors.New("sandbox: not running")
	}
	return windows.TerminateProcess(s.process, killExitCode)
}

// Destroy kills the run through its Job and reaps it.
func (s *windowsSandbox) Destroy() error {
	if s.process == 0 {
		return nil
	}
	if !s.outcome.ended() {
		s.bounds.kill()
	}
	_, err := s.Wait()
	return err
}

// Stats returns the run's accounting facts: the Job's, live while
// the run goes on and final after Wait.
func (s *windowsSandbox) Stats() (Stats, error) {
	if s.process == 0 {
		return Stats{}, errors.New("sandbox: not started")
	}
	s.mu.Lock()
	final := s.final
	s.mu.Unlock()
	if final != nil {
		return *final, nil
	}
	return s.bounds.stats()
}

// securityCapabilities is the SECURITY_CAPABILITIES the process's
// attribute list carries: the container's SID and the capabilities
// granted.
type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

const procThreadAttributeSecurityCapabilities = 0x00020009

// networkCapabilities are the capability SIDs that open the network
// to a container: the internet as a client and a server, the private
// network as a client and a server.
func networkCapabilities() (*windows.SIDAndAttributes, uint32, error) {
	var caps []windows.SIDAndAttributes
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinCapabilityInternetClientSid, windows.WinCapabilityInternetClientServerSid, windows.WinCapabilityPrivateNetworkClientServerSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, 0, err
		}
		caps = append(caps, windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_ENABLED})
	}
	return &caps[0], uint32(len(caps)), nil
}

// descriptors serializes this process's writes of security
// descriptors: a write reads the entry list, changes it and writes it
// back, which two runs of one process over one directory would race.
// Two processes racing the same descriptor are not serialized here.
var descriptors sync.Mutex

// errReachedAlready is admit's answer where the entry needs none:
// the platform grants every package what the directory already
// allows, and the caller may not write its descriptor.
var errReachedAlready = errors.New("reached by every package already")

// readAccess is what a grant read and executed carries; writeAccess
// what a read-write one carries besides: data written and entries
// made, renamed and deleted — never the permissions or the owner,
// which a payload could turn to its own ends past the run.
const (
	readAccess      = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
	writeAccess     = readAccess | windows.FILE_GENERIC_WRITE | windows.DELETE | fileDeleteChild
	fileDeleteChild = 0x0040 // FILE_DELETE_CHILD: entries beneath a directory deleted
)

// admit adds an inheriting entry for the container to the path's
// security descriptor. Where the descriptor may not be written and
// the directory already allows every package what the entry would
// (the platform's own directories, System32 among them), the entry
// is not needed and errReachedAlready says so.
func admit(path string, sid *windows.SID, write bool) error {
	access := windows.ACCESS_MASK(readAccess)
	if write {
		access = writeAccess
	}
	descriptors.Lock()
	defer descriptors.Unlock()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, old)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && !write && allPackagesAllowed(old, access) {
			return errReachedAlready
		}
		return err
	}
	return nil
}

// allPackagesAllowed reports whether the ACL allows every package
// (ALL APPLICATION PACKAGES) the access, in an inheriting entry.
func allPackagesAllowed(acl *windows.ACL, access windows.ACCESS_MASK) bool {
	if acl == nil {
		return false
	}
	all, err := windows.CreateWellKnownSid(windows.WinBuiltinAnyPackageSid)
	if err != nil {
		return false
	}
	ace := unsafe.Add(unsafe.Pointer(acl), unsafe.Sizeof(*acl))
	for i := 0; i < int(acl.AceCount); i++ {
		h := (*windows.ACE_HEADER)(ace)
		if h.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			a := (*windows.ACCESS_ALLOWED_ACE)(ace)
			sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
			generic := windows.ACCESS_MASK(windows.GENERIC_READ | windows.GENERIC_EXECUTE)
			if sid.Equals(all) && h.AceFlags&windows.CONTAINER_INHERIT_ACE != 0 && (a.Mask&access == access || a.Mask&generic == generic || a.Mask&windows.GENERIC_ALL != 0) {
				return true
			}
		}
		ace = unsafe.Add(ace, h.AceSize)
	}
	return false
}

// relieve removes the container's entries from the path's security
// descriptor.
func relieve(path string, sid *windows.SID) error {
	if sid == nil {
		return nil
	}
	descriptors.Lock()
	defer descriptors.Unlock()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.REVOKE_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, old)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
