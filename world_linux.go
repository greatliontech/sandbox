//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/greatliontech/sandbox/internal/nslinux"
)

// mounts is the caller's mount table, read once per resolution from
// mountinfo: what tells the mounts beneath a directory and, for a
// mount that grafts a directory of one filesystem onto another path
// (a bind mount of a directory, whose root within its filesystem is
// that directory), the spellings its origin has — every mount of the
// same filesystem presenting that directory or one above it.
type mounts struct {
	table *nslinux.Mounts
}

func readMounts() (*mounts, error) {
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	return &mounts{table: nslinux.NewMounts(nslinux.ParseMountinfo(info), nslinux.MountID)}, nil
}

// beneath lists the mounts strictly beneath the canonical directory
// dir that a path reaches, or whose mount point cannot be read,
// each with the spellings its origin has, told from the listing
// alone: the mount point need not be readable for them.
func (m *mounts) beneath(dir string) []mountBeneath {
	visible, unread := m.table.Beneath(dir)
	var out []mountBeneath
	for _, r := range append(visible, unread...) {
		mb := mountBeneath{point: r.Point, origins: m.originsOf(r, r.Root)}
		if r.Type == autofs {
			mb.err = errUntriggered
		}
		out = append(out, mb)
	}
	return out
}

// autofs is the filesystem type of an automount point not yet
// triggered: the mount a lookup there replaces with what the map
// says.
const autofs = "autofs"

// untriggered reports whether the canonical path p is an automount
// point not yet triggered.
func (m *mounts) untriggered(p string) bool {
	mt, err := m.table.At(p)
	return err == nil && mt.Point == p && mt.Type == autofs
}

// origins lists the spellings the canonical path p has besides its
// own: p names, within the filesystem of the mount it reaches, the
// mount's root joined with the rest of p, and every other mount of
// that filesystem presenting that path or a directory above it
// spells the same entry under its own mount point (originsOf).
func (m *mounts) origins(p string) ([]string, error) {
	mt, err := m.table.At(p)
	if err != nil {
		return nil, err
	}
	return m.originsOf(*mt, filepath.Join(mt.Root, strings.TrimPrefix(p, mt.Point))), nil
}

// originsOf lists the spellings of the path fsPath within the
// filesystem of the mount mt, under every other mount of that
// filesystem presenting that path or a directory above it — unless
// a mount hanging beneath that one covers the spelling on the way,
// told from the listing's parent ids so that no path is walked that
// could fire an automount; a spelling that cannot be read is kept
// for the caller to judge. Each spelling names the one filesystem
// path, so there are at most as many as there are mounts. A bind whose origin no mount in view presents (a file
// bound into a container from a filesystem the container does not
// mount) has no spelling here but its own: nothing in this
// namespace reaches its origin's ancestors. A mount whose root is a
// deleted directory presents nothing that can gain an entry.
func (m *mounts) originsOf(mt nslinux.Mount, fsPath string) []string {
	var out []string
	for _, o := range m.table.Records() {
		if o.ID == mt.ID || o.Dev != mt.Dev || strings.HasSuffix(o.Root, "//deleted") {
			continue
		}
		var s string
		switch {
		case o.Root == "/":
			s = filepath.Join(o.Point, fsPath)
		case fsPath == o.Root:
			s = o.Point
		case within(fsPath, o.Root):
			s = filepath.Join(o.Point, strings.TrimPrefix(fsPath, o.Root))
		default:
			continue
		}
		if m.table.Covers(o, s) {
			continue // a mount beneath o on the way: that spelling reaches another entry
		}
		out = append(out, s)
	}
	return out
}
