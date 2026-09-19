//go:build linux

package nslinux

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockABI reports the Landlock ABI version this kernel exposes,
// or why Landlock is unavailable: a kernel without the syscalls
// (ENOSYS) or built without the LSM, or one where it is not enabled
// at boot (EOPNOTSUPP). Every version from 1 handles the filesystem
// access rights; 2 adds file reparenting (refer), 3 truncation, 4
// the TCP rights, 5 device ioctls.
func LandlockABI() (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, fmt.Errorf("landlock: %w", errno)
	}
	return int(r), nil
}

// The filesystem access rights by the ABI that introduced them.
const (
	landlockFSv1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	landlockFSv2 = unix.LANDLOCK_ACCESS_FS_REFER
	landlockFSv3 = unix.LANDLOCK_ACCESS_FS_TRUNCATE
	landlockFSv5 = unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	landlockNetv4 = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP

	// landlockScopedv6 confines the domain's IPC with processes
	// outside it: abstract unix sockets and signals (ABI 6).
	landlockScopedv6 = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL

	// landlockRulePathBeneath is LANDLOCK_RULE_PATH_BENEATH, the one
	// rule type the filesystem allowlist uses.
	landlockRulePathBeneath = 1
)

// LandlockFS is every filesystem access right ABI abi handles: the
// set a ruleset restricts, so an access outside a rule's grant is
// denied.
func LandlockFS(abi int) uint64 {
	rights := uint64(landlockFSv1)
	if abi >= 2 {
		rights |= landlockFSv2
	}
	if abi >= 3 {
		rights |= landlockFSv3
	}
	if abi >= 5 {
		rights |= landlockFSv5
	}
	return rights
}

// LandlockRead is the right to read files and list directories under
// a path.
func LandlockRead() uint64 {
	return unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
}

// LandlockExecute is the right to execute files under a path.
func LandlockExecute() uint64 { return unix.LANDLOCK_ACCESS_FS_EXECUTE }

// LandlockScopesIPC reports whether ABI abi confines a domain's
// abstract unix sockets and signals to the domain.
func LandlockScopesIPC(abi int) bool { return abi >= 6 }

// landlockFileRights are the rights that apply to a file rather than
// a directory: a rule on a file may carry no other, the kernel
// refusing a directory-only right on a file with EINVAL.
const landlockFileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

// LandlockRule allows Access beneath Path: a directory, or a file,
// on which the directory-only rights are dropped at application —
// what a file can be granted is what Access says of files.
type LandlockRule struct {
	Path   string `json:"path"`
	Access uint64 `json:"access"`
}

// RestrictLandlock confines the calling thread — and so what it
// execs — to the rules: every filesystem right the ABI handles is
// denied except where a rule allows it beneath its path; where
// denyTCP and the ABI handles the TCP rights, binding and connecting
// TCP sockets are denied outright; and where the ABI scopes IPC,
// abstract unix sockets and signals reach only processes in the
// domain — the process's own descendants. no_new_privs is set
// first, as the kernel requires of an unprivileged restriction.
// Irreversible; exec must follow on this thread, which stays
// pinned. A rule's path gone since the caller resolved it is
// reported as such.
func RestrictLandlock(abi int, rules []LandlockRule, denyTCP bool) error {
	if abi < 1 {
		return errors.New("landlock: no ABI to apply")
	}
	attr := unix.LandlockRulesetAttr{Access_fs: LandlockFS(abi)}
	if denyTCP && abi >= 4 {
		attr.Access_net = landlockNetv4
	}
	if LandlockScopesIPC(abi) {
		attr.Scoped = landlockScopedv6
	}
	runtime.LockOSThread() // no unlock: exec follows
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock: create ruleset: %w", errno)
	}
	ruleset := int(fd)
	defer unix.Close(ruleset)
	for _, r := range rules {
		if r.Access&^LandlockFS(abi) != 0 {
			return fmt.Errorf("landlock: rule %s asks a right ABI %d does not handle", r.Path, abi)
		}
		parent, err := unix.Open(r.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("landlock: rule %s: %w", r.Path, err)
		}
		access := r.Access
		var st unix.Stat_t
		if err := unix.Fstat(parent, &st); err != nil {
			unix.Close(parent)
			return fmt.Errorf("landlock: rule %s: %w", r.Path, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			access &= landlockFileRights
		}
		beneath := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(parent)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), landlockRulePathBeneath, uintptr(unsafe.Pointer(&beneath)), 0, 0, 0)
		unix.Close(parent)
		if errno != 0 {
			return fmt.Errorf("landlock: rule %s: %w", r.Path, errno)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if _, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("landlock: restrict: %w", errno)
	}
	return nil
}
