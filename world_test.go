//go:build linux || darwin

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveTreeRefusals pins the tree resolution's refusals every
// platform shares: a file grant with more than one name on the host,
// and a rendezvous directory that is no directory.
func TestResolveTreeRefusals(t *testing.T) {
	root := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "payload"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	linked := filepath.Join(host, "linked")
	if err := os.WriteFile(linked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linked, filepath.Join(host, "other-name")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, host), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, linked), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	none := func(string) error { return nil }
	_, err = resolveTree(Spec{Exec: "/payload", Root: root, PathGrants: []PathGrant{{Path: linked, Access: ReadWrite}}}, none)
	if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "names on the host") {
		t.Errorf("a hard-linked file grant: %v, want refused by its names", err)
	}
	rtFile := filepath.Join(host, "rt")
	if err := os.WriteFile(rtFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, rtFile), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = resolveTree(Spec{Exec: "/payload", Root: root, RuntimeDir: rtFile}, none)
	if !errors.Is(err, ErrUndeliverable) || !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("a rendezvous file: %v, want refused as no directory", err)
	}
	_ = exe
}
