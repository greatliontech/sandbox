//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/greatliontech/sandbox/internal/nslinux"
)

// TestOriginSpellings pins the spellings a path has through the
// mount table, over synthetic tables: a bind of a directory spelled
// under the filesystem's root mount and the reverse; a directory
// bound onto its own ancestor, whose derived spelling reaches the
// bind again and so is no spelling of the origin (and whose listing
// ends); a mount shadowed by a later mount over its parent, which
// no path reaches, the visible mount's origin spelled instead; a
// caller whose "/" is itself a bind of a directory, spelled under
// another mount of the filesystem with the separator kept.
func TestOriginSpellings(t *testing.T) {
	for _, c := range []struct {
		name  string
		ids   map[string]int // the kernel's word where the table's longest point is not it
		recs  []nslinux.Mount
		path  string
		wants []string
	}{
		{"a bind of a directory", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "8:1", Root: "/tmp/parent", Point: "/q"}}, "/q/tree", []string{"/tmp/parent/tree"}},
		{"the origin of a bound directory", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "8:1", Root: "/tmp/parent", Point: "/q"}}, "/tmp/parent/tree", []string{"/q/tree"}},
		{"the bound directory itself", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "8:1", Root: "/tmp/parent", Point: "/q"}}, "/tmp/parent", []string{"/q"}},
		{"another filesystem", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "0:50", Root: "/", Point: "/tmp"}}, "/tmp/x", nil},
		{"a directory bound onto its ancestor", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "8:1", Root: "/b/c", Point: "/b"}}, "/b/x", nil},
		{"a mount shadowed by a later mount over its parent", map[string]int{"/a/b/tree": 3, "/data/parent/b/tree": 1}, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "0:50", Root: "/", Point: "/a/b"}, {ID: 3, Parent: 1, Dev: "8:1", Root: "/data/parent", Point: "/a"}}, "/a/b/tree", []string{"/data/parent/b/tree"}},
		{"a root that is a bind of a directory", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/var/lib/machines/x", Point: "/"}, {ID: 2, Parent: 1, Dev: "8:1", Root: "/", Point: "/host"}}, "/home/u", []string{"/host/var/lib/machines/x/home/u"}},
		{"a spelling reaching a mount the listing lacks, kept", map[string]int{"/q/tree": 999}, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "8:1", Root: "/tmp/parent", Point: "/q"}}, "/tmp/parent/tree", []string{"/q/tree"}},
		{"a spelling covered by a mount hanging beneath the presenting mount", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "8:1", Root: "/tmp/parent", Point: "/q"}, {ID: 3, Parent: 1, Dev: "0:60", Root: "/", Point: "/tmp/parent/tree"}}, "/q/tree/x", nil},
		{"a whole filesystem mounted twice", nil, []nslinux.Mount{{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/"}, {ID: 2, Parent: 1, Dev: "0:50", Root: "/", Point: "/a"}, {ID: 3, Parent: 1, Dev: "0:50", Root: "/", Point: "/b"}}, "/a/x", []string{"/b/x"}},
	} {
		byPoint := idsByPoint(c.recs)
		m := &mounts{table: nslinux.NewMounts(c.recs, func(p string) (int, error) {
			if id, ok := c.ids[p]; ok {
				return id, nil
			}
			return byPoint(p)
		})}
		got, err := m.origins(c.path)
		if err != nil || !slices.Equal(got, c.wants) {
			t.Errorf("%s: origins(%s) = %v, %v; want %v", c.name, c.path, got, err, c.wants)
		}
	}
}

// idsByPoint tells the mount a path reaches from a table alone: the
// listed mount whose point is the longest prefix of the path, the
// last listed on a tie.
func idsByPoint(recs []nslinux.Mount) func(string) (int, error) {
	return func(p string) (int, error) {
		best := -1
		for i, r := range recs {
			if (r.Point == p || within(p, r.Point)) && (best < 0 || len(r.Point) >= len(recs[best].Point)) {
				best = i
			}
		}
		if best < 0 {
			return 0, &os.PathError{Op: "statx", Path: p, Err: syscall.ENOENT}
		}
		return recs[best].ID, nil
	}
}

// TestUntriggeredAutomount pins that an automount point not yet
// triggered beneath a grant, or as the grant, is unread: what it
// names is unjudged.
func TestUntriggeredAutomount(t *testing.T) {
	recs := []nslinux.Mount{
		{ID: 1, Parent: 0, Dev: "8:1", Root: "/", Point: "/", Type: "ext4"},
		{ID: 2, Parent: 1, Dev: "0:70", Root: "/", Point: "/g/auto", Type: "autofs"},
	}
	m := &mounts{table: nslinux.NewMounts(recs, idsByPoint(recs))}
	beneath := m.beneath("/g")
	if len(beneath) != 1 || beneath[0].point != "/g/auto" || beneath[0].err != errUntriggered {
		t.Errorf("beneath(/g) = %+v, want the automount unread", beneath)
	}
	if !m.untriggered("/g/auto") || m.untriggered("/g") {
		t.Error("untriggered: want the automount point alone")
	}
}

// TestBarred pins what makes an unreadable spelling unjudged: a
// directory the caller owns barring it; one another user closed, or
// a spelling naming nothing, leaves it out.
func TestBarred(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	own := t.TempDir()
	if err := os.Mkdir(filepath.Join(own, "closed"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(own, "closed"), 0o700) })
	_, err := os.Stat(filepath.Join(own, "closed", "x"))
	if err == nil {
		t.Fatal("the closed directory bars nothing")
	}
	if !barred(filepath.Join(own, "closed", "x"), err) {
		t.Error("a directory of the caller's own, closed: want barred")
	}
	_, err = os.Stat("/proc/1/fd/0")
	if err == nil {
		t.Skip("another's directory is open to this caller")
	}
	if barred("/proc/1/fd/0", err) {
		t.Error("a directory another user closed: want left out")
	}
	if barred(filepath.Join(own, "absent"), syscall.ENOENT) {
		t.Error("a spelling naming nothing: want left out")
	}
	if !barred(filepath.Join(own, "x"), syscall.EIO) {
		t.Error("a failure of another kind: want unjudged")
	}
}
