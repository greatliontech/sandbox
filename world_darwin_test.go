//go:build darwin

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAutomountMarked pins this platform's marking of an automount
// point not yet triggered, over a mount table told to the resolution
// rather than read from a host that may run no automounter: a
// stated point is unread as such with no origins asked for, and one
// beneath a grant is unread among the grant's mounts.
func TestAutomountMarked(t *testing.T) {
	dir := must(filepath.EvalSymlinks(t.TempDir()))
	auto := filepath.Join(dir, "a")
	if err := os.MkdirAll(auto, 0o755); err != nil {
		t.Fatal(err)
	}
	// The stated point is spelled through a symlink, so that origins
	// asked for would add the kernel's spelling on any host.
	link := filepath.Join(t.TempDir(), "l")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	stated := filepath.Join(link, "a")
	m := &mounts{points: []string{"/", dir, auto}, types: map[string]string{"/": "apfs", dir: "apfs", auto: "autofs", stated: "autofs"}}
	e, unread, err := spellingsOf(m, stated)
	if err != nil || len(e) != 1 || len(unread) != 1 || !strings.Contains(unread[0], "an automount not yet triggered") {
		t.Fatalf("a stated automount point: %d spellings, unread %v, %v; want its own lineage alone and the unread mark", len(e), unread, err)
	}
	_, unread, err = hostEntry(m, dir, true)
	if err != nil || len(unread) != 1 || !strings.HasPrefix(unread[0], auto+" cannot be read (an automount not yet triggered") {
		t.Fatalf("an automount beneath a grant: unread %v, %v; want the point unread as such", unread, err)
	}
	if !m.untriggered(auto) || m.untriggered(dir) {
		t.Error("untriggered: want the automount point alone")
	}
}
