//go:build windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// row is one rung of the ladder (docs/specs/sandbox.md, "Mechanism
// ladder") this backend delivers on windows. The OS row is an
// AppContainer: a process under a package identity of the run's own,
// which reaches nothing the platform does not grant every package
// (the system's own files and services) or the run's grants do not
// name, its network withheld unless granted; the Minimal row is a
// Job Object's bounds alone, in the caller's own world, graded for
// nothing else. The kill tie is the Job on both: every process of
// the run is born into it and dies with its last handle.
type row struct {
	tier Isolation
}

var (
	osRow      = row{tier: OS}
	minimalRow = row{tier: Minimal}
)

// refuses names the intent in spec the row cannot deliver, if any.
// Neither row presents a hostname, and neither bounds an open-file
// count: a Job Object limits memory, CPU time and the process count
// and nothing of handles (docs/specs/sandbox.md, "Bounded means
// bounded"). The OS row refuses a Root until its world under one is
// delivered. The Minimal row's mechanism set is bounds alone: it
// refuses every intent only a security boundary delivers — a Root, a
// denied network, a read-only grant — and a Spec stating no limits,
// which would leave that row nothing to apply (sandbox never
// bare-execs).
func (r row) refuses(spec Spec) error {
	undeliverable := func(what string) error {
		return fmt.Errorf("%w: the %s row %s", ErrUndeliverable, r.tier, what)
	}
	if spec.Hostname != "" {
		return undeliverable("presents no hostname")
	}
	if spec.Limits.MaxFiles > 0 {
		return undeliverable("bounds no open-file count: a Job Object limits memory, CPU time and the process count alone")
	}
	if spec.Root != "" {
		return undeliverable("cannot restrict the world to a Root")
	}
	if r.tier == OS {
		return nil
	}
	if !spec.Network {
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
	// appContainer: the platform makes an AppContainer profile for
	// this user and launches a process under it.
	appContainer error
}

// selectRow picks the highest row whose facts hold and names, where
// a row is passed over, what fails for it. The OS row needs an
// AppContainer; the Minimal row always holds: a Job Object is always
// there.
func selectRow(f hostFacts) (row, []string) {
	if f.appContainer == nil {
		return osRow, nil
	}
	return minimalRow, []string{f.appContainer.Error()}
}

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

// probeHost asks the platform for an AppContainer profile of its own
// and gives it back: a platform that refuses one (an edition without
// the API, a policy denying this user) is the fact that the OS row
// is out of reach; any other failure is an anomaly, not an answer.
func probeHost(ctx context.Context) (hostFacts, error) {
	var f hostFacts
	if err := userenv.Load(); err != nil {
		f.appContainer = fmt.Errorf("appcontainer: %v", err)
		return f, nil
	}
	p, err := newProfile("probe")
	if err != nil {
		f.appContainer = fmt.Errorf("appcontainer: %v", err)
		return f, nil
	}
	if err := p.delete(); err != nil {
		return f, fmt.Errorf("sandbox: appcontainer probe: %w", err)
	}
	return f, nil
}

var (
	userenv                           = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile     = userenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile     = userenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSidFromName = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// profile is an AppContainer profile of this user's: the package
// identity a run's processes carry, made for the run and deleted at
// its end. The platform keeps a directory per profile (the package's
// own, under the user's local application data), which the run's
// processes may write and which goes with the profile.
type profile struct {
	name string
	sid  *windows.SID
}

// profiles numbers the profiles this process makes, so that two runs
// of one process never share a name.
var profiles atomic.Uint64

// newProfile makes a profile named for this process and the purpose,
// its SID derived where one of that name already exists (a run of
// this pid ended without deleting it).
func newProfile(purpose string) (*profile, error) {
	name := "sandbox-" + purpose + "-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(profiles.Add(1), 10)
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	r, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if hr := uint32(r); hr != 0 {
		if hr != hresultAlreadyExists {
			return nil, fmt.Errorf("CreateAppContainerProfile %s: %w", name, hresult(hr))
		}
		r, _, _ := procDeriveAppContainerSidFromName.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid)))
		if hr := uint32(r); hr != 0 {
			return nil, fmt.Errorf("DeriveAppContainerSidFromAppContainerName %s: %w", name, hresult(hr))
		}
	}
	return &profile{name: name, sid: sid}, nil
}

// delete removes the profile and its package directory.
func (p *profile) delete() error {
	n, err := windows.UTF16PtrFromString(p.name)
	if err != nil {
		return err
	}
	r, _, _ := procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(n)))
	if hr := uint32(r); hr != 0 {
		return fmt.Errorf("DeleteAppContainerProfile %s: %w", p.name, hresult(hr))
	}
	if p.sid != nil {
		windows.FreeSid(p.sid)
		p.sid = nil
	}
	return nil
}

const hresultAlreadyExists = 0x800700B7 // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)

// hresult reads an HRESULT as an error: a wrapped Win32 code as that
// errno, any other as its number.
func hresult(hr uint32) error {
	if hr&0xFFFF0000 == 0x80070000 {
		return windows.Errno(hr & 0xFFFF)
	}
	return errors.New("HRESULT " + strconv.FormatUint(uint64(hr), 16))
}
