//go:build linux

package nslinux

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// PrivatizeMounts recursively marks the mount tree private, so mounts
// and unmounts made here stop propagating to the host. Kernel
// preconditions: a mount namespace owned by (or nested under) a user
// namespace the caller holds CAP_SYS_ADMIN in. Required before
// PivotRoot: pivoting away from a shared root fails with EINVAL.
func PrivatizeMounts() error {
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("privatize mounts: %w", err)
	}
	return nil
}

// BindMount recursively bind-mounts source onto target. Kernel
// preconditions: CAP_SYS_ADMIN in the mount namespace's owning user
// namespace; target must exist (a directory for a directory source, a
// file for a file source).
func BindMount(source, target string) error {
	if err := unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s -> %s: %w", source, target, err)
	}
	return nil
}

// PivotRoot makes newRoot the mount namespace's root filesystem and
// detaches the old root, leaving no path back to the host tree. The
// old root is parked on a scratch directory inside newRoot and lazily
// unmounted, so nothing of the host remains reachable afterwards.
// Kernel preconditions: CAP_SYS_ADMIN in the owning user namespace;
// the current root must not be MS_SHARED (see PrivatizeMounts);
// newRoot is made a mount point here via a self-bind, as pivot_root
// requires. newRoot must be writable — the scratch directory is
// created in it, so any read-only remount of the tree comes after —
// and must not already contain a ".pivot_root" entry: a leftover
// from elsewhere is refused before anything is pivoted.
func PivotRoot(newRoot string) error {
	if err := unix.Mount(newRoot, newRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("pivot_root: self-bind %s: %w", newRoot, err)
	}

	oldRoot := filepath.Join(newRoot, ".pivot_root")
	if err := os.Mkdir(oldRoot, 0o700); err != nil {
		return fmt.Errorf("pivot_root: scratch dir: %w", err)
	}

	if err := unix.PivotRoot(newRoot, oldRoot); err != nil {
		return fmt.Errorf("pivot_root %s: %w", newRoot, err)
	}

	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("pivot_root: chdir /: %w", err)
	}

	oldRoot = "/.pivot_root"
	if err := unix.Unmount(oldRoot, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("pivot_root: detach old root: %w", err)
	}
	if err := os.Remove(oldRoot); err != nil {
		return fmt.Errorf("pivot_root: remove scratch dir: %w", err)
	}
	return nil
}

// RemountRootReadOnly remounts the namespace's root mount read-only,
// repeating the root mount's locked flags (see lockedMountFlags).
// This mount only: a remount changes per-mount flags and never
// recurses, so submounts (path grants, the rendezvous directory)
// keep their own access — a read-only grant is made read-only itself
// via RemountReadOnly. Kernel preconditions: CAP_SYS_ADMIN in the
// owning user namespace; typically called after PivotRoot so "/" is
// the sandbox tree.
func RemountRootReadOnly() error {
	locked, err := lockedMountFlags("/")
	if err != nil {
		return fmt.Errorf("read-only root: %w", err)
	}
	flags := unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | locked
	if err := unix.Mount("", "/", "", uintptr(flags), ""); err != nil {
		return fmt.Errorf("read-only root: %w", err)
	}
	return nil
}

// RemountReadOnly makes an existing mount at path read-only: a
// recursive self-bind (so path is its own mount, submounts carried)
// followed by a read-only remount repeating the mount's locked
// flags. The remount affects that mount only — it never recurses, so
// a submount under path keeps its own access. Kernel preconditions:
// CAP_SYS_ADMIN in the owning user namespace; path must exist.
func RemountReadOnly(path string) error {
	if err := unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("read-only %s: self-bind: %w", path, err)
	}
	locked, err := lockedMountFlags(path)
	if err != nil {
		return fmt.Errorf("read-only %s: %w", path, err)
	}
	flags := unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | locked
	if err := unix.Mount(path, path, "", uintptr(flags), ""); err != nil {
		return fmt.Errorf("read-only %s: remount: %w", path, err)
	}
	return nil
}

// lockedMountFlags returns the mount flags a read-only remount of
// path must repeat inside a user namespace: the kernel locks a
// mount's nosuid/nodev/noexec and atime attributes when the namespace
// cannot see their origin, and a remount that drops a locked flag
// fails with EPERM. Reading them from statfs keeps the remount
// faithful to whatever the host mounted. A strictatime mount needs
// no repeating: since kernel 3.17 a remount naming no atime flag
// preserves the existing atime mode.
func lockedMountFlags(path string) (uintptr, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return lockedFlags(int64(sfs.Flags)), nil
}

// lockedFlags maps the statfs flag word to the mount flags a remount
// must repeat. Split from lockedMountFlags so the mapping is testable
// without a mount namespace.
func lockedFlags(statfsFlags int64) uintptr {
	var flags uintptr
	if statfsFlags&unix.ST_NOSUID != 0 {
		flags |= unix.MS_NOSUID
	}
	if statfsFlags&unix.ST_NODEV != 0 {
		flags |= unix.MS_NODEV
	}
	if statfsFlags&unix.ST_NOEXEC != 0 {
		flags |= unix.MS_NOEXEC
	}
	if statfsFlags&unix.ST_NOATIME != 0 {
		flags |= unix.MS_NOATIME
	}
	if statfsFlags&unix.ST_NODIRATIME != 0 {
		flags |= unix.MS_NODIRATIME
	}
	if statfsFlags&unix.ST_RELATIME != 0 {
		flags |= unix.MS_RELATIME
	}
	return flags
}
