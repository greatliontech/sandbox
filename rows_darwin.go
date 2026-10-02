//go:build darwin

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// row is one rung of the ladder (docs/specs/sandbox.md, "Mechanism
// ladder") this backend delivers on darwin. The OS row is a Seatbelt
// profile applied by the platform's sandbox-exec: a filesystem
// allowlist and the network denied; the Minimal row is bounds
// alone, in the caller's own world, graded for nothing else. Neither
// row has namespaces: the kill tie is the process group on both, and
// darwin has no parent-death tie at all (docs/specs/sandbox.md, "No
// orphans").
type row struct {
	tier Isolation
}

var (
	osRow      = row{tier: OS}
	minimalRow = row{tier: Minimal}
)

// refuses names the intent in spec the row cannot deliver, if any.
// The OS row presents no hostname (no UTS namespace on this
// platform). The Minimal row's mechanism set is bounds alone: it
// refuses every intent only a security boundary delivers — a Root,
// a hostname, a denied network, a read-only grant — and a Spec
// stating no limits, which would leave that row nothing to apply
// (docs/specs/sandbox.md, the ladder: sandbox never bare-execs).
func (r row) refuses(spec Spec) error {
	undeliverable := func(what string) error {
		return fmt.Errorf("%w: the %s row %s", ErrUndeliverable, r.tier, what)
	}
	if r.tier == OS {
		if spec.Hostname != "" {
			return undeliverable("presents no hostname")
		}
		return nil
	}
	switch {
	case spec.Root != "":
		return undeliverable("cannot restrict the world to a Root")
	case spec.Hostname != "":
		return undeliverable("presents no hostname")
	case !spec.Network:
		return undeliverable("cannot deny the network: Network must be granted to run on it")
	}
	for _, g := range spec.PathGrants {
		if g.Access == ReadOnly {
			return undeliverable(fmt.Sprintf("cannot make grant %s read-only", g.Path))
		}
	}
	if spec.Limits == (Limits{}) {
		return undeliverable("applies bounds only, and none were stated: sandbox never bare-execs")
	}
	return nil
}

// hostFacts are the probed facts row selection reads: the reason
// the fact does not hold on this host, or nil where it does.
type hostFacts struct {
	// seatbelt: the platform's sandbox-exec is present and applies a
	// profile to this binary.
	seatbelt error
}

// selectRow picks the highest row whose facts hold and names, where
// a row is passed over, what fails for it. The OS row needs Seatbelt;
// the Minimal row always holds: rlimits and the watchdog are always
// there.
func selectRow(f hostFacts) (row, []string) {
	if f.seatbelt == nil {
		return osRow, nil
	}
	return minimalRow, []string{f.seatbelt.Error()}
}

// sandboxExec is the platform's profile applier: it compiles a
// profile, applies it to itself and execs the command in place, so
// the command runs under the profile at the same pid.
const sandboxExec = "/usr/bin/sandbox-exec"

// host caches the probed facts; hostOverride is the seam tests set to
// exercise every row on one host.
var (
	host         probeCache[hostFacts]
	hostOverride *hostFacts
)

func hostFactsFor(ctx context.Context) (hostFacts, error) {
	if hostOverride != nil {
		return *hostOverride, nil
	}
	return host.get(ctx, "", probeHost)
}

// probeHost asks the platform: sandbox-exec applying a profile that
// allows everything to this binary under the probe marker, which
// exits at once (runInit). A missing sandbox-exec, or one that cannot
// apply the profile (its own exit, with what it said), is the fact
// that the OS row is out of reach; the probe child dying otherwise is
// an anomaly, not an answer, as on every platform (docs/specs/
// sandbox.md, Re-exec).
func probeHost(ctx context.Context) (hostFacts, error) {
	var f hostFacts
	self, err := selfExecutable()
	if err != nil {
		return f, fmt.Errorf("sandbox: seatbelt probe: %w", err)
	}
	if _, err := os.Stat(sandboxExec); err != nil {
		f.seatbelt = fmt.Errorf("seatbelt: %s: %v", sandboxExec, err)
		return f, nil
	}
	cmd := exec.CommandContext(ctx, sandboxExec, "-p", "(version 1)(allow default)", self)
	cmd.Env = append(hostEnv(), envInit+"=1", envProbe+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return f, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if msg := strings.TrimSpace(string(out)); strings.HasPrefix(msg, "sandbox-exec:") {
			f.seatbelt = fmt.Errorf("seatbelt: %s", msg)
			return f, nil
		}
		return f, fmt.Errorf("sandbox: seatbelt probe: the re-exec'd init died (%v): a package init of this binary must not act under %s", err, envInit)
	}
	return f, fmt.Errorf("sandbox: seatbelt probe: %w", err)
}

// selfExecutable is this binary's path as the platform spells it,
// symlinks resolved: the profile allowlists it by that spelling, and
// Seatbelt matches canonical paths.
func selfExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// killRun issues the strongest kill the run holds on this platform:
// the process group, which a payload can leave with setsid (docs/
// specs/sandbox.md, "No orphans"). The group is addressed by the
// leader's pid, checked alive through os.Process first, as the Linux
// rows do.
func killRun(p *os.Process) error {
	err := p.Signal(syscall.Signal(0))
	if err != nil {
		return nil
	}
	if kerr := syscall.Kill(-p.Pid, syscall.SIGKILL); kerr != nil && !errors.Is(kerr, syscall.ESRCH) {
		return kerr
	}
	return nil
}

// sysProcAttr puts the run in a process group of its own, for the
// group kill to reach.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
