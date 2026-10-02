package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// treeFor lays out a tree for the resolution: an entrypoint, an
// "etc" directory, and the same name beside the tree on the host.
func treeFor(t *testing.T) string {
	t.Helper()
	tree := must(canonical(t.TempDir()))
	for _, d := range []string{filepath.Join(tree, "etc"), filepath.Join(filepath.Dir(tree), "etc")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tree, "payload"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	return tree
}

// TestWorkDirClampedAtTree pins the working directory delivered
// under a Root: the stated path's ".." is clamped at the tree, so
// the directory is the tree's own under that name, never the host's
// beside the tree.
func TestWorkDirClampedAtTree(t *testing.T) {
	tree := treeFor(t)
	w, err := resolveTree(Spec{Exec: "/payload", Root: tree, WorkDir: "/../etc"}, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(tree, "etc"); w.hostWorkDir != want {
		t.Fatalf("hostWorkDir = %q, want %q", w.hostWorkDir, want)
	}
}

// TestRendezvousFileRefused pins a refusal every platform shares: a
// rendezvous directory that is no directory.
func TestRendezvousFileRefused(t *testing.T) {
	tree := treeFor(t)
	host := t.TempDir()
	rt := filepath.Join(host, "rt")
	if err := os.WriteFile(rt, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if grantsLandInTree {
		if err := os.MkdirAll(filepath.Join(tree, host), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tree, rt), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := resolveTree(Spec{Exec: "/payload", Root: tree, RuntimeDir: rt}, func(string) error { return nil })
	if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("a rendezvous file: %v, want refused as no directory", err)
	}
}
