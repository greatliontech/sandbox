//go:build linux

package nslinux

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLockedFlagsMapsEachLockableAttribute(t *testing.T) {
	cases := []struct {
		name   string
		statfs int64
		want   uintptr
	}{
		{"none", 0, 0},
		{"nosuid", unix.ST_NOSUID, unix.MS_NOSUID},
		{"nodev", unix.ST_NODEV, unix.MS_NODEV},
		{"noexec", unix.ST_NOEXEC, unix.MS_NOEXEC},
		{"noatime", unix.ST_NOATIME, unix.MS_NOATIME},
		{"nodiratime", unix.ST_NODIRATIME, unix.MS_NODIRATIME},
		{"relatime", unix.ST_RELATIME, unix.MS_RELATIME},
		{
			"all combined",
			unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC | unix.ST_NOATIME | unix.ST_NODIRATIME | unix.ST_RELATIME,
			unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME | unix.MS_NODIRATIME | unix.MS_RELATIME,
		},
		// Read-only is not a locked *attribute* — the remount sets
		// MS_RDONLY itself — and statfs exposes no strictatime bit,
		// so neither may leak into the repeated set.
		{"rdonly ignored", unix.ST_RDONLY, 0},
		{"rdonly plus nosuid", unix.ST_RDONLY | unix.ST_NOSUID, unix.MS_NOSUID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockedFlags(tc.statfs); got != tc.want {
				t.Errorf("lockedFlags(%#x) = %#x, want %#x", tc.statfs, got, tc.want)
			}
		})
	}
}

func TestLockedMountFlagsFailsLoudOnStatfsError(t *testing.T) {
	// A path that cannot be statfs'd cannot have its locked flags
	// repeated; proceeding would trade the real diagnostic for a
	// confusing kernel EPERM, so the verb refuses instead.
	if _, err := lockedMountFlags("/nonexistent/nslinux-test"); err == nil {
		t.Error("want error when statfs fails")
	}
}

// idsByPoint tells the mount a path reaches from a table alone: the
// listed mount whose point is the longest prefix of the path, the
// last listed on a tie — the shape of a tree with no moves and no
// mounts over mounts — and refuses the paths named unreadable.
func idsByPoint(recs []Mount, unreadable ...string) func(string) (int, error) {
	return func(p string) (int, error) {
		if slices.Contains(unreadable, p) {
			return 0, &os.PathError{Op: "statx", Path: p, Err: unix.EACCES}
		}
		best := -1
		for i, r := range recs {
			if (r.Point == p || beneathPath(p, r.Point)) && (best < 0 || len(r.Point) >= len(recs[best].Point)) {
				best = i
			}
		}
		if best < 0 {
			return 0, &os.PathError{Op: "statx", Path: p, Err: unix.ENOENT}
		}
		return recs[best].ID, nil
	}
}

// mountSubtree lists the mount at path and its descendants by parent
// id, shallowest first, decoding mountinfo's octal escapes; mounts
// an earlier bind at the same path is covered by, and mounts beside
// the subtree, are left out.
func TestMountSubtree(t *testing.T) {
	info := []byte(strings.Join([]string{
		"22 1 0:21 / /proc rw - proc proc rw",
		"40 1 0:30 / /dev rw - devtmpfs devtmpfs rw",
		"41 40 0:31 / /dev/shm rw - tmpfs tmpfs rw",
		"43 1 0:33 / /devices rw - tmpfs tmpfs rw",
		"50 40 0:30 / /dev rw - devtmpfs devtmpfs rw",
		"51 50 0:32 / /dev/pts rw - devpts devpts rw",
		"52 50 0:34 / /dev/with\\040space rw - tmpfs tmpfs rw",
		"53 52 0:35 / /dev/with\\040space/deep rw - tmpfs tmpfs rw",
	}, "\n"))
	recs := ParseMountinfo(info)
	if recs[0].Type != "proc" || recs[6].Type != "tmpfs" {
		t.Fatalf("types = %q, %q; want proc and tmpfs", recs[0].Type, recs[6].Type)
	}
	ids := idsByPoint(recs)
	got := mountSubtree(info, "/dev/", ids)
	want := []string{"/dev", "/dev/pts", "/dev/with space", "/dev/with space/deep"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("mountSubtree = %v, want %v", got, want)
	}
	if got := mountSubtree(info, "/nowhere", ids); len(got) != 0 {
		t.Fatalf("mountSubtree(/nowhere) = %v", got)
	}
}

// The mount a path reaches is the kernel's word, not the listing's
// order: a mount moved under a later-listed mount is reached through
// it, a mount mounted over is reached by no path, and a mount point
// that cannot be read is listed apart as one that may reach its
// mount.
func TestMountsByKernelWord(t *testing.T) {
	recs := []Mount{
		{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"},
		{ID: 584, Parent: 585, Dev: "8:1", Root: "/home/u/parent", Point: "/x/a/b"}, // moved under 585 after 585 was mounted
		{ID: 585, Parent: 1, Dev: "0:50", Root: "/", Point: "/x/a"},
		{ID: 590, Parent: 1, Dev: "0:51", Root: "/", Point: "/x/c"}, // covered by 591
		{ID: 591, Parent: 1, Dev: "0:52", Root: "/", Point: "/x/c"},
		{ID: 592, Parent: 1, Dev: "0:53", Root: "/", Point: "/x/locked/m"},
		{ID: 593, Parent: 1, Dev: "0:54", Root: "/", Point: "/x/auto"}, // an automount point, mounted over since the listing
	}
	ids := map[string]int{"/x/a/b/tree": 584, "/x/a/b": 584, "/x/a": 585, "/x/c": 591, "/x/c/f": 591, "/": 1, "/x": 1, "/x/auto": 999}
	m := NewMounts(recs, func(p string) (int, error) {
		if id, ok := ids[p]; ok {
			return id, nil
		}
		return 0, &os.PathError{Op: "statx", Path: p, Err: unix.EACCES}
	})
	if at, err := m.At("/x/a/b/tree"); err != nil || at == nil || at.ID != 584 {
		t.Errorf("At(/x/a/b/tree) = %+v, %v; want the moved mount", at, err)
	}
	if at, err := m.At("/x/c/f"); err != nil || at == nil || at.ID != 591 {
		t.Errorf("At(/x/c/f) = %+v, %v; want the mount over", at, err)
	}
	if _, err := m.At("/x/locked/m"); err == nil {
		t.Error("At of an unreadable point: want the error")
	}
	visible, unread := m.Beneath("/x")
	var ids2 []int
	for _, r := range visible {
		ids2 = append(ids2, r.ID)
	}
	if !slices.Equal(ids2, []int{584, 585, 591}) {
		t.Errorf("Beneath(/x) = %v, want [584 585 591]", ids2)
	}
	if len(unread) != 2 || unread[0].ID != 592 || unread[1].ID != 593 {
		t.Errorf("Beneath(/x) unread = %v, want the unreadable point's mount and the one the kernel names unlisted", unread)
	}
	if _, err := m.At("/x/auto"); !errors.Is(err, ErrUnlisted) {
		t.Errorf("At of a point reaching an unlisted mount: %v, want ErrUnlisted", err)
	}
	// A spelling through a mount is covered by a mount hanging beneath
	// it, by parent ids: the moved mount under 585 covers /x/a/b and
	// what lies beneath, not /x/a/c; a mount beside it covers nothing.
	o := recs[2]
	for p, want := range map[string]bool{"/x/a/b": true, "/x/a/b/tree": true, "/x/a": false, "/x/a/c": false} {
		if got := m.Covers(o, p); got != want {
			t.Errorf("Covers(585, %s) = %v, want %v", p, got, want)
		}
	}
	if m.Covers(recs[0], "/x/c/f") != true {
		t.Error("Covers(1, /x/c/f): the mounts at /x/c hang under 1, want covered")
	}
	// A presenting mount covered itself: a mount stacked on its point
	// from it, or hung over an ancestor of its point from a mount
	// above it, which no path through it survives; its own ancestors
	// cover nothing.
	stacked := NewMounts([]Mount{
		{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"},
		{ID: 2, Parent: 1, Dev: "8:1", Root: "/data", Point: "/srv/view"},
		{ID: 3, Parent: 2, Dev: "0:80", Root: "/", Point: "/srv/view"},
		{ID: 4, Parent: 1, Dev: "8:1", Root: "/data", Point: "/mnt/view"},
		{ID: 5, Parent: 1, Dev: "0:81", Root: "/", Point: "/mnt"},
	}, func(string) (int, error) { return 0, os.ErrNotExist })
	for _, c := range []struct {
		o    int
		p    string
		want bool
	}{{2, "/srv/view/x", true}, {2, "/srv/view", true}, {4, "/mnt/view/x", true}, {1, "/etc/x", false}, {1, "/srv/view/x", true}} {
		if got := stacked.Covers(stacked.recs[stacked.index[c.o]], c.p); got != c.want {
			t.Errorf("Covers(%d, %s) = %v, want %v", c.o, c.p, got, c.want)
		}
	}
	// A mount hidden beside the chain covers nothing: c at x/y hangs
	// from the root, inside the region of the bind at x attached
	// after it, which hides it; o at x/y/z hangs from that bind.
	hidden := NewMounts([]Mount{
		{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"},
		{ID: 584, Parent: 1, Dev: "0:90", Root: "/", Point: "/cv/x/y"},
		{ID: 585, Parent: 1, Dev: "8:1", Root: "/cv/S", Point: "/cv/x"},
		{ID: 586, Parent: 585, Dev: "0:91", Root: "/", Point: "/cv/x/y/z"},
	}, func(string) (int, error) { return 0, os.ErrNotExist })
	if hidden.Covers(hidden.recs[3], "/cv/x/y/z/parent/tree") {
		t.Error("Covers(o at /cv/x/y/z): the hidden sibling at /cv/x/y counted as covering")
	}
}

// A listing with no mount at path refuses instead of covering nothing.
func TestReadOnlySubtreeRefusesUnlistedPath(t *testing.T) {
	info := []byte("40 1 0:30 / /dev rw - devtmpfs devtmpfs rw\n")
	ids := idsByPoint(ParseMountinfo(info))
	if got, err := readOnlySubtree(info, "/dev", ids); err != nil || len(got) != 1 {
		t.Fatalf("readOnlySubtree(/dev) = %v, %v", got, err)
	}
	if _, err := readOnlySubtree(info, "/link-to-dev", ids); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("readOnlySubtree(unlisted) = %v, want the refusal", err)
	}
}
