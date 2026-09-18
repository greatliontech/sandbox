//go:build linux

package nslinux

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
// detaches the old root, leaving no path back to the host tree, and
// writes nothing into newRoot: pivot_root accepts the new root as its
// own put-old location, stacking the old root on top of it, and a
// lazy unmount from that stacked mount then peels the old root away.
// A read-only tree — a shared, content-addressed image export — is
// therefore a valid new root. Kernel preconditions: CAP_SYS_ADMIN in
// the owning user namespace; the current root must not be MS_SHARED
// (see PrivatizeMounts); newRoot is made a mount point here via a
// self-bind, as pivot_root requires.
func PivotRoot(newRoot string) error {
	if err := unix.Mount(newRoot, newRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("pivot_root: self-bind %s: %w", newRoot, err)
	}
	// The old root is held by descriptor: after the pivot it is
	// reachable only as the mount stacked on the new root, and the
	// descriptor is how this process steps onto it to detach it.
	oldRoot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("pivot_root: open old root: %w", err)
	}
	defer unix.Close(oldRoot)

	if err := unix.Chdir(newRoot); err != nil {
		return fmt.Errorf("pivot_root: chdir %s: %w", newRoot, err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root %s: %w", newRoot, err)
	}
	if err := unix.Fchdir(oldRoot); err != nil {
		return fmt.Errorf("pivot_root: step onto old root: %w", err)
	}
	// Belt and braces over the documented precondition: the tree is
	// private, so the detach cannot propagate; marking the old root
	// slave keeps that true even for a caller that skipped
	// PrivatizeMounts.
	if err := unix.Mount("", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("pivot_root: isolate old root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("pivot_root: detach old root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("pivot_root: chdir /: %w", err)
	}
	return nil
}

// RemountRootReadOnly remounts the namespace's root mount read-only,
// repeating the root mount's locked flags (see lockedMountFlags).
// This mount only: a remount changes per-mount flags and never
// recurses, so submounts (path grants, the rendezvous directory)
// keep their own access. Kernel preconditions: CAP_SYS_ADMIN in the
// owning user namespace; typically called after PivotRoot so "/" is
// the sandbox tree.
func RemountRootReadOnly() error {
	return remountReadOnly("/")
}

// RemountReadOnlyTree makes the mount at path and every mount beneath
// it read-only: a recursive self-bind first (so path is its own mount,
// submounts carried), then a read-only remount of each mount in that
// bind's subtree — the mount just created and its descendants by
// parent id, listed from mountinfo, which is why the verb runs where
// /proc is still visible — repeating every mount's own locked flags.
// A read-only grant means the whole subtree, not the top mount with
// writable submounts beneath it. path must be canonical (no symlink
// at any component): mountinfo records canonical mount points, and a
// listing that does not show the bind at path is refused rather than
// remounting nothing. Kernel preconditions: CAP_SYS_ADMIN in the
// owning user namespace; path must exist.
func RemountReadOnlyTree(path, mountinfo string) error {
	if err := unix.Mount(path, path, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("read-only %s: self-bind: %w", path, err)
	}
	info, err := os.ReadFile(mountinfo)
	if err != nil {
		return fmt.Errorf("read-only %s: %w", path, err)
	}
	mounts, err := readOnlySubtree(info, path)
	if err != nil {
		return err
	}
	for _, mp := range mounts {
		if err := remountReadOnly(mp); err != nil {
			return err
		}
	}
	return nil
}

// remountReadOnly remounts one existing mount read-only, repeating
// its locked flags.
func remountReadOnly(mountpoint string) error {
	locked, err := lockedMountFlags(mountpoint)
	if err != nil {
		return fmt.Errorf("read-only %s: %w", mountpoint, err)
	}
	flags := unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | locked
	if err := unix.Mount("", mountpoint, "", uintptr(flags), ""); err != nil {
		return fmt.Errorf("read-only %s: remount: %w", mountpoint, err)
	}
	return nil
}

// readOnlySubtree is the set of mounts a read-only remount of path
// must cover, refusing — never silently covering nothing — when the
// listing shows no mount at path: the self-bind guarantees one at
// the canonical path, so its absence means path was not canonical.
func readOnlySubtree(mountinfo []byte, path string) ([]string, error) {
	mounts := mountSubtree(mountinfo, path)
	if len(mounts) == 0 {
		return nil, fmt.Errorf("read-only %s: the bind is not listed at that path (a symlink on the way?)", path)
	}
	return mounts, nil
}

// mountSubtree lists, from a mountinfo listing, the topmost mount at
// path — the last record naming it: mountinfo is emitted in attach
// order (the namespace list's tail before kernel 6.8, the rbtree of
// unique, monotonic mount ids since), so the last record at a path
// is the mount most recently attached there — and every mount
// beneath it by parent id, shallowest first. Mounts
// the top one shadows (older mounts at or under the same path) are
// not its descendants and are left out: they are no longer reachable
// by path. Empty when no mount is recorded at path. Fields 1 and 2
// of a record are the mount id and its parent's; field 5 is the
// mount point, with octal escapes for the characters mountinfo
// cannot print.
func mountSubtree(mountinfo []byte, path string) []string {
	path = filepath.Clean(path)
	type rec struct {
		id, parent int
		mp         string
	}
	var recs []rec
	top := -1
	for _, line := range strings.Split(string(mountinfo), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		id, err1 := strconv.Atoi(f[0])
		parent, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		r := rec{id: id, parent: parent, mp: unescapeMountinfo(f[4])}
		if r.mp == path {
			top = len(recs)
		}
		recs = append(recs, r)
	}
	if top < 0 {
		return nil
	}
	children := map[int][]rec{}
	for _, r := range recs {
		children[r.parent] = append(children[r.parent], r)
	}
	var out []string
	queue := []rec{recs[top]}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		out = append(out, r.mp)
		queue = append(queue, children[r.id]...)
	}
	return out
}

// unescapeMountinfo decodes mountinfo's octal escapes (\040 for a
// space, \011 for a tab, \012 for a newline, \134 for a backslash).
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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
