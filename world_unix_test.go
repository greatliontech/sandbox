//go:build linux || darwin

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHardLinkedFileGrantRefused pins a refusal of the rows whose
// grants land in the tree: a file grant with more than one name on
// the host, which could be the tree's own file under another.
func TestHardLinkedFileGrantRefused(t *testing.T) {
	tree := treeFor(t)
	host := t.TempDir()
	linked := filepath.Join(host, "linked")
	if err := os.WriteFile(linked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linked, filepath.Join(host, "other-name")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, host), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, linked), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := resolveTree(Spec{Exec: "/payload", Root: tree, PathGrants: []PathGrant{{Path: linked, Access: ReadWrite}}}, func(string) error { return nil })
	if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "names on the host") {
		t.Errorf("a hard-linked file grant: %v, want refused by its names", err)
	}
}

// TestWorkDirWalkedThroughLink pins the working directory delivered
// under a Root as the rooted process resolves it: ".." after a
// symlink climbs from the link's target, not from the link.
func TestWorkDirWalkedThroughLink(t *testing.T) {
	tree := treeFor(t)
	if err := os.Mkdir(filepath.Join(tree, "etc", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("etc/sub", filepath.Join(tree, "l")); err != nil {
		t.Fatal(err)
	}
	w, err := resolveTree(Spec{Exec: "/payload", Root: tree, WorkDir: "/l/.."}, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(tree, "etc"); w.hostWorkDir != want {
		t.Fatalf("hostWorkDir = %q, want %q", w.hostWorkDir, want)
	}
}
