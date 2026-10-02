//go:build linux

package nslinux

import (
	"errors"
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
	mounts, err := readOnlySubtree(info, path, MountID)
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
func readOnlySubtree(mountinfo []byte, path string, mountID func(string) (int, error)) ([]string, error) {
	mounts := mountSubtree(mountinfo, path, mountID)
	if len(mounts) == 0 {
		return nil, fmt.Errorf("read-only %s: the bind is not listed at that path (a symlink on the way?)", path)
	}
	return mounts, nil
}

// Mount is one record of a mountinfo listing: the mount's id and its
// parent's (fields 1 and 2), the mounted filesystem's device as
// major:minor (field 3), the root of the mount within that
// filesystem (field 4, "/" for the whole of it, a directory's path
// for a bind of that directory), the mount point (field 5), the
// paths with mountinfo's octal escapes decoded, and the filesystem
// type (the field after the separator).
type Mount struct {
	ID, Parent int
	Dev        string
	Root       string
	Point      string
	Type       string
}

// ParseMountinfo reads a mountinfo listing's records in their listed
// order — attach order: the namespace list's tail before kernel 6.8,
// the rbtree of unique, monotonic mount ids since — so the last
// record at a path is the mount most recently attached there.
// Records it cannot read are left out.
func ParseMountinfo(mountinfo []byte) []Mount {
	var recs []Mount
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
		r := Mount{ID: id, Parent: parent, Dev: f[2], Root: unescapeMountinfo(f[3]), Point: unescapeMountinfo(f[4])}
		for i := 6; i+1 < len(f); i++ {
			if f[i] == "-" {
				r.Type = f[i+1]
				break
			}
		}
		recs = append(recs, r)
	}
	return recs
}

// Mounts is a mountinfo listing read as the mount tree it describes,
// with the kernel's own word on which mount a path reaches (MountID):
// the listing alone cannot tell, a mount moved under another keeping
// its place in it, and a mount mounted over hides what it covers.
type Mounts struct {
	recs    []Mount
	index   map[int]int // mount id to its record
	mountID func(path string) (int, error)
}

// NewMounts reads the listing's records into the tree; mountID
// tells the id of the mount a path reaches (MountID on a live
// host).
func NewMounts(recs []Mount, mountID func(path string) (int, error)) *Mounts {
	m := &Mounts{recs: recs, index: map[int]int{}, mountID: mountID}
	for i, r := range recs {
		m.index[r.ID] = i
	}
	return m
}

// Records lists every record, in listed order.
func (m *Mounts) Records() []Mount { return m.recs }

// At is the mount the path p reaches, as the kernel reports it; the
// error says where p cannot be read, or where the kernel names a
// mount the listing lacks (one attached since the listing was read,
// which is ErrUnlisted).
func (m *Mounts) At(p string) (*Mount, error) {
	id, err := m.mountID(p)
	if err != nil {
		return nil, err
	}
	i, ok := m.index[id]
	if !ok {
		return nil, &os.PathError{Op: "mount", Path: p, Err: ErrUnlisted}
	}
	return &m.recs[i], nil
}

// ErrUnlisted is the kernel naming, for a path, a mount the listing
// read for the resolution lacks.
var ErrUnlisted = errors.New("reaches a mount not in the listing")

// Beneath lists the mounts strictly beneath the canonical directory
// dir that their own mount points reach — a mount covered by another
// is not among them, no path reaching it — and, apart, those whose
// mount points could not be read, which may reach their mounts.
func (m *Mounts) Beneath(dir string) (visible, unread []Mount) {
	for _, r := range m.recs {
		if !beneathPath(r.Point, dir) {
			continue
		}
		at, err := m.At(r.Point)
		if err != nil {
			unread = append(unread, r)
			continue
		}
		if at.ID == r.ID {
			visible = append(visible, r)
		}
	}
	return visible, unread
}

// Covers reports whether the path p, spelled through the mount o
// (p at or beneath o's point), reaches another mount instead: one
// covering o itself — a mount stacked on o, or one hanging from a
// member A of o's ancestor chain at or above the point of the next
// member below A, which cannot have been there before that member
// was attached beneath it (it would hang beneath the newcomer) and
// so lies over it, where one strictly inside that member's region
// is hidden by it instead — or a listed mount descending from o by
// parent ids whose point lies on the way from o's point to p, p
// itself included. Parent ids are the kernel's own word on where a
// mount hangs, moves included, so no path need be walked.
func (m *Mounts) Covers(o Mount, p string) bool {
	chain := []Mount{o} // o first, then each ancestor
	below := map[int]Mount{}
	seen := map[int]bool{o.ID: true}
	for r := o; ; {
		i, ok := m.index[r.Parent]
		if !ok || seen[r.Parent] {
			break
		}
		seen[r.Parent] = true
		below[r.Parent] = r
		r = m.recs[i]
		chain = append(chain, r)
	}
	for _, c := range m.recs {
		if seen[c.ID] {
			continue
		}
		if c.Parent == o.ID {
			if c.Point == o.Point {
				return true // stacked on o
			}
			if (c.Point == p || beneathPath(p, c.Point)) && beneathPath(c.Point, o.Point) {
				return true // beneath o, on the way
			}
			continue
		}
		if b, ok := below[c.Parent]; ok && (c.Point == b.Point || beneathPath(b.Point, c.Point)) {
			return true // over a member of o's chain
		}
		if (c.Point == p || beneathPath(p, c.Point)) && beneathPath(c.Point, o.Point) && m.descends(c, o.ID) {
			return true // beneath o, on the way
		}
	}
	return false
}

// descends reports whether r lies under the mount with id ancestor
// in the tree by parent ids.
func (m *Mounts) descends(r Mount, ancestor int) bool {
	seen := map[int]bool{}
	for r.ID != ancestor {
		i, ok := m.index[r.Parent]
		if !ok || seen[r.ID] {
			return false
		}
		seen[r.ID] = true
		r = m.recs[i]
	}
	return true
}

// subtree lists the mount at path, where the mount path reaches is
// mounted exactly there, and every mount beneath it by parent id,
// shallowest first.
func (m *Mounts) subtree(path string) []string {
	top, err := m.At(path)
	if err != nil || top.Point != path {
		return nil
	}
	children := map[int][]Mount{}
	for _, r := range m.recs {
		children[r.Parent] = append(children[r.Parent], r)
	}
	var out []string
	queue := []Mount{*top}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		out = append(out, r.Point)
		queue = append(queue, children[r.ID]...)
	}
	return out
}

// beneathPath reports whether the canonical path p lies strictly
// beneath the canonical directory dir — every path but "/" lies
// beneath "/".
func beneathPath(p, dir string) bool {
	if dir == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, dir+"/")
}

// MountID is the id, as mountinfo lists it, of the mount the path
// reaches: statx's mount id where the kernel reports one (5.8), the
// mount id in the fdinfo of a path descriptor otherwise. Neither
// triggers an automount at the path: statx honours AT_NO_AUTOMOUNT
// only when asked (stat always passes it), and a path descriptor
// carries no intent to open.
func MountID(path string) (int, error) {
	var stx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, path, unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &stx)
	if err == nil && stx.Mask&unix.STATX_MNT_ID != 0 {
		return int(stx.Mnt_id), nil
	}
	if err != nil && !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) {
		return 0, &os.PathError{Op: "statx", Path: path, Err: err}
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(info), "\n") {
		if v, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, fmt.Errorf("%s: no mount id in its fdinfo", path)
}

// mountSubtree lists, from a mountinfo listing, the mount at path —
// the one path reaches, which a self-bind has just made the newest
// there — and every mount beneath it by parent id, shallowest
// first. Mounts the top one covers are not its descendants and are
// left out: no path reaches them. Empty when no mount is recorded
// at path; mountID tells the mount a path reaches.
func mountSubtree(mountinfo []byte, path string, mountID func(string) (int, error)) []string {
	return NewMounts(ParseMountinfo(mountinfo), mountID).subtree(filepath.Clean(path))
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
