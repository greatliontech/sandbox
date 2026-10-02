//go:build linux || darwin

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The unix rows' reading of the host: an entry's identity is its
// device and inode, ownership the effective user's, and a grant
// under a Root lands in the tree, which a row with mount namespaces
// presents at "/".

// identityOf reads an entry's identity: its device and inode.
func identityOf(p string) (identity, error) {
	st, err := stat(p)
	if err != nil {
		return identity{}, err
	}
	return identity{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// ownsEntry reports whether the effective user owns the entry: the
// one a change of its permissions is allowed to.
func ownsEntry(p string) (bool, error) {
	st, err := stat(p)
	if err != nil {
		return false, err
	}
	return int(st.Uid) == os.Geteuid(), nil
}

// fileLinks counts the names a file has on the host.
func fileLinks(p string) (uint64, error) {
	st, err := stat(p)
	if err != nil {
		return 0, err
	}
	return uint64(st.Nlink), nil
}

func stat(p string) (*syscall.Stat_t, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: no inode", p)
	}
	return st, nil
}

// canonical is a path's canonical spelling: every symlink resolved.
func canonical(p string) (string, error) { return filepath.EvalSymlinks(p) }

// grantsLandInTree: a grant under a Root lands on the entry the
// caller placed in the tree at the grant's own path, where a row
// presenting the tree at "/" binds it (docs/specs/sandbox.md, "Root
// is world-restriction").
const grantsLandInTree = true

// resolveInTree resolves a tree-absolute path as the rooted process
// will see it (statInTree).
func resolveInTree(root, p string) (os.FileInfo, string, error) {
	return statInTree(root, p)
}

// statInTree stats a tree-absolute path the way the pivoted process
// will see it: symlinks are chased inside the tree, an absolute
// target re-rooted at the tree and ".." clamped at it, with the
// kernel's own bound on chained links. root must be canonical.
func statInTree(root, p string) (os.FileInfo, string, error) {
	const maxLinks = 40
	links := 0
	// rest holds the components still to walk; cur is the tree-absolute
	// directory resolved so far. The stated path is walked as written:
	// a lexical clean-up would apply ".." before the symlink it
	// follows, which is not what the kernel does.
	rest := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := "/"
	for len(rest) > 0 {
		seg := rest[0]
		rest = rest[1:]
		switch seg {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, seg)
		fi, err := os.Lstat(filepath.Join(root, next))
		if err != nil {
			return nil, "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if len(rest) == 0 {
				return fi, next, nil
			}
			if !fi.IsDir() {
				return nil, "", &os.PathError{Op: "stat", Path: p, Err: syscall.ENOTDIR}
			}
			cur = next
			continue
		}
		links++
		if links > maxLinks {
			return nil, "", &os.PathError{Op: "stat", Path: p, Err: syscall.ELOOP}
		}
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil {
			return nil, "", err
		}
		// The link's target is cleaned only of its spelling (trailing
		// slashes); its own ".." components are walked like any other.
		targetSegs := strings.Split(strings.Trim(target, "/"), "/")
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = append(targetSegs, rest...)
	}
	fi, err := os.Lstat(filepath.Join(root, cur))
	return fi, cur, err
}
