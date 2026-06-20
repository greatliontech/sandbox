//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// Internal re-exec protocol.
//
// Start re-execs /proc/self/exe with envInit set; the init() below intercepts
// that, reads the init config from a pipe (envInitFD), applies sandbox setup
// inside the freshly created namespaces, then execs the target. The namespaces
// themselves are created by the Go runtime at clone time via SysProcAttr — no
// cgo, and identical isolation to a C-driven clone.
const (
	envInit   = "_SANDBOX_INIT"
	envInitFD = "_SANDBOX_INITFD"
)

// RLIMIT_NPROC is not exported by the standard syscall package on Linux.
const rlimitNPROC = 6

func init() {
	if os.Getenv(envInit) == "1" {
		runInit() // never returns
	}
}

// initConfig is the JSON payload handed to the re-exec'd init process.
type initConfig struct {
	Hostname string       `json:"hostname,omitempty"`
	Root     string       `json:"root,omitempty"`
	WorkDir  string       `json:"workdir,omitempty"`
	Rlimits  []rlimitSpec `json:"rlimits,omitempty"`
	Cmd      string       `json:"cmd"`
	Args     []string     `json:"args,omitempty"`
	Env      []string     `json:"env,omitempty"`
}

type rlimitSpec struct {
	Resource int    `json:"resource"`
	Value    uint64 `json:"value"`
}

type linuxSandbox struct {
	spec   Spec
	cmd    *exec.Cmd
	exited bool
}

func newSandbox(spec Spec) (Sandbox, error) {
	if spec.Exec == "" {
		return nil, errors.New("sandbox: Spec.Exec is required")
	}
	// The create-only Linux backend is always kernel-enforced (Strong); refuse
	// up front if the caller demanded something we structurally cannot exceed.
	if spec.MinTier > Strong {
		return nil, ErrWeakerThanRequired
	}
	return &linuxSandbox{spec: spec}, nil
}

func (s *linuxSandbox) Tier() Isolation { return Strong }

func (s *linuxSandbox) Start(ctx context.Context) error {
	if s.cmd != nil {
		return errors.New("sandbox: already started")
	}
	if s.spec.Root != "" {
		// Rootfs pivot + bind-mounts land next; the namespace core is proven
		// first. Fail loud rather than silently ignore the request.
		return errors.New("sandbox: Spec.Root not yet implemented")
	}

	cfg := initConfig{
		Hostname: s.spec.Hostname,
		Root:     s.spec.Root,
		WorkDir:  s.spec.WorkDir,
		Rlimits:  buildRlimits(s.spec.Limits),
		Cmd:      s.spec.Exec,
		Args:     s.spec.Args,
		Env:      s.spec.Env,
	}

	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("sandbox: config pipe: %w", err)
	}

	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Stdin = s.spec.Stdin
	cmd.Stdout = s.spec.Stdout
	cmd.Stderr = s.spec.Stderr
	cmd.ExtraFiles = []*os.File{r} // becomes fd 3 in the child
	cmd.Env = append(os.Environ(),
		envInit+"=1",
		envInitFD+"=3",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  cloneFlags(s.spec.Network),
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// GidMappingsEnableSetgroups defaults false → Go writes "deny" to
		// /proc/<pid>/setgroups, required for an unprivileged gid_map.
		Pdeathsig: syscall.SIGKILL, // child dies if the host process dies
	}

	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return fmt.Errorf("sandbox: start: %w", err)
	}
	// Child holds its own copy of r; close ours.
	r.Close()

	if err := json.NewEncoder(w).Encode(&cfg); err != nil {
		w.Close()
		_ = cmd.Process.Kill()
		return fmt.Errorf("sandbox: write init config: %w", err)
	}
	w.Close()

	s.cmd = cmd
	return nil
}

func (s *linuxSandbox) Wait() (ExitStatus, error) {
	if s.cmd == nil {
		return ExitStatus{}, errors.New("sandbox: not started")
	}
	err := s.cmd.Wait()
	s.exited = true

	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return ExitStatus{}, err
	}
	ps := s.cmd.ProcessState
	es := ExitStatus{Code: ps.ExitCode()}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		es.Signaled = true
		es.Signal = ws.Signal()
		es.Code = 128 + int(ws.Signal())
	}
	return es, nil
}

func (s *linuxSandbox) Signal(sig os.Signal) error {
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("sandbox: not started")
	}
	return s.cmd.Process.Signal(sig)
}

func (s *linuxSandbox) Destroy() error {
	if s.cmd == nil || s.cmd.Process == nil || s.exited {
		return nil
	}
	return s.cmd.Process.Kill()
}

func (s *linuxSandbox) Stats() (Stats, error) { return Stats{}, nil }

// cloneFlags returns the namespace creation flags. Network isolation (a new,
// empty net namespace) is the default; granting network shares the host's.
func cloneFlags(network bool) uintptr {
	flags := uintptr(syscall.CLONE_NEWUSER |
		syscall.CLONE_NEWNS |
		syscall.CLONE_NEWPID |
		syscall.CLONE_NEWUTS |
		syscall.CLONE_NEWIPC)
	if !network {
		flags |= syscall.CLONE_NEWNET
	}
	return flags
}

func buildRlimits(l Limits) []rlimitSpec {
	var out []rlimitSpec
	if l.MemoryBytes > 0 {
		out = append(out, rlimitSpec{Resource: syscall.RLIMIT_AS, Value: l.MemoryBytes})
	}
	if l.CPUSeconds > 0 {
		out = append(out, rlimitSpec{Resource: syscall.RLIMIT_CPU, Value: l.CPUSeconds})
	}
	if l.MaxFiles > 0 {
		out = append(out, rlimitSpec{Resource: syscall.RLIMIT_NOFILE, Value: l.MaxFiles})
	}
	if l.MaxProcs > 0 {
		out = append(out, rlimitSpec{Resource: rlimitNPROC, Value: l.MaxProcs})
	}
	return out
}

// --- re-exec'd init side ---

func runInit() {
	if err := doInit(); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-init:", err)
		os.Exit(127)
	}
	// doInit execs the target and never returns on success.
	os.Exit(127)
}

func doInit() error {
	fdStr := os.Getenv(envInitFD)
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return fmt.Errorf("bad %s=%q: %w", envInitFD, fdStr, err)
	}
	f := os.NewFile(uintptr(fd), "sandbox-config")
	if f == nil {
		return fmt.Errorf("invalid config fd %d", fd)
	}
	var cfg initConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		f.Close()
		return fmt.Errorf("decode config: %w", err)
	}
	f.Close()

	if cfg.Hostname != "" {
		if err := syscall.Sethostname([]byte(cfg.Hostname)); err != nil {
			return fmt.Errorf("sethostname: %w", err)
		}
	}
	if cfg.WorkDir != "" {
		if err := syscall.Chdir(cfg.WorkDir); err != nil {
			return fmt.Errorf("chdir %s: %w", cfg.WorkDir, err)
		}
	}
	for _, rl := range cfg.Rlimits {
		lim := syscall.Rlimit{Cur: rl.Value, Max: rl.Value}
		if err := syscall.Setrlimit(rl.Resource, &lim); err != nil {
			return fmt.Errorf("setrlimit %d: %w", rl.Resource, err)
		}
	}

	env := cfg.Env
	if env == nil {
		env = cleanEnv(os.Environ())
	}
	argv := append([]string{cfg.Cmd}, cfg.Args...)
	if err := syscall.Exec(cfg.Cmd, argv, env); err != nil {
		return fmt.Errorf("exec %s: %w", cfg.Cmd, err)
	}
	return nil
}

// cleanEnv strips the internal re-exec markers from an inherited environment.
func cleanEnv(env []string) []string {
	out := env[:0:0]
	for _, e := range env {
		if strings.HasPrefix(e, envInit+"=") || strings.HasPrefix(e, envInitFD+"=") {
			continue
		}
		out = append(out, e)
	}
	return out
}
