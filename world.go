//go:build linux || darwin

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// bind is one path exposed into the world: the host source, the
// canonical target it lands on (inside the tree under a Root, the
// canonical host path otherwise), and whether it is read-only.
type bind struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// treeWorld is the platform-neutral resolution of a spec's world: the
// canonical root where one is stated, the entrypoint resolved inside
// the tree as a tree-absolute path (the stated path otherwise), and
// the binds — each grant and the rendezvous directory at the
// canonical target it lands on. A platform's row maps it to its
// mechanism: a pivot and binds, an allowlist at host paths.
type treeWorld struct {
	root  string
	exec  string
	binds []bind
}

// resolveTree checks, before anything runs, that every stated intent
// has somewhere to land, and resolves the world to canonical paths —
// the one place the grant-to-target mapping is computed, on every
// platform (docs/specs/sandbox.md, "Root is world-restriction").
// Under a Root: the Root is a directory, canonicalized; the
// entrypoint and the working directory resolve inside the tree as a
// file and a directory, symlinks chased exactly as a process rooted
// there would chase them (absolute targets re-rooted at the tree,
// ".." clamped at it), the entrypoint then held to checkEntry at its
// host path; each grant and the rendezvous directory exist on the
// host and in the tree as the same kind of entry, reached through no
// symlink at any component — a bind would follow a symlink into the
// host view and the rooted process into the tree, so the grant would
// land where the process cannot see it. Without a Root, the
// entrypoint is held to checkEntry as stated, and grants need only
// exist on the host, their targets the canonical host paths — the
// mount table records canonical mount points, and a read-only
// remount must find its own bind there. Grants may not overlap one
// another or the rendezvous directory. A failure is ErrUndeliverable:
// the host cannot do what was asked. The spelling and length checks
// of the entrypoint, the working directory and the hostname, and the
// row's own refusals, are the caller's, before this.
func resolveTree(spec Spec, checkEntry func(hostPath string) error) (treeWorld, error) {
	undeliverable := func(format string, a ...any) (treeWorld, error) {
		return treeWorld{}, fmt.Errorf("%w: "+format, append([]any{ErrUndeliverable}, a...)...)
	}
	t := treeWorld{exec: spec.Exec}
	var root string
	if spec.Root == "" {
		if err := checkEntry(spec.Exec); err != nil {
			return undeliverable("exec %s: %v", spec.Exec, err)
		}
	} else {
		var err error
		root, err = filepath.EvalSymlinks(spec.Root)
		if err != nil {
			return undeliverable("root %s: %v", spec.Root, err)
		}
		fi, err := os.Stat(root)
		if err != nil {
			return undeliverable("root %s: %v", spec.Root, err)
		}
		if !fi.IsDir() {
			return undeliverable("root %s is not a directory", spec.Root)
		}
		fi, resolved, err := statInTree(root, spec.Exec)
		if err != nil {
			return undeliverable("exec %s is not in the tree: %v", spec.Exec, err)
		}
		if fi.IsDir() {
			return undeliverable("exec %s is a directory in the tree", spec.Exec)
		}
		if err := checkEntry(filepath.Join(root, resolved)); err != nil {
			return undeliverable("exec %s: %v", spec.Exec, err)
		}
		t.root = root
		t.exec = resolved
		if spec.WorkDir != "" {
			fi, _, err := statInTree(root, spec.WorkDir)
			if err != nil {
				return undeliverable("workdir %s is not in the tree: %v", spec.WorkDir, err)
			}
			if !fi.IsDir() {
				return undeliverable("workdir %s is not a directory in the tree", spec.WorkDir)
			}
		}
	}
	// A grant whose host path lies within the tree, or holds it — the
	// host's root over the tree's included — would make the tree
	// writable through the grant, which "never written" forbids;
	// judged on the host paths before anything else is asked of them.
	if root != "" {
		type stated struct{ path, what string }
		var paths []stated
		for _, g := range spec.PathGrants {
			paths = append(paths, stated{g.Path, "grant"})
		}
		if spec.RuntimeDir != "" {
			paths = append(paths, stated{spec.RuntimeDir, "runtime dir"})
		}
		for _, p := range paths {
			if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path {
				continue // resolveGrant refuses it by name
			}
			host, err := filepath.EvalSymlinks(p.path)
			if err != nil {
				continue // resolveGrant refuses it by name
			}
			switch {
			case host == root:
				return undeliverable("%s %s is the tree %s", p.what, p.path, spec.Root)
			case within(host, root):
				return undeliverable("%s %s lies within the tree %s", p.what, p.path, spec.Root)
			case within(root, host):
				return undeliverable("%s %s holds the tree %s", p.what, p.path, spec.Root)
			}
		}
	}
	var binds []bind
	for _, g := range spec.PathGrants {
		b, err := resolveGrant(root, g.Path, "grant")
		if err != nil {
			return treeWorld{}, err
		}
		b.ReadOnly = g.Access == ReadOnly
		binds = append(binds, b)
	}
	if spec.RuntimeDir != "" {
		b, err := resolveGrant(root, spec.RuntimeDir, "runtime dir")
		if err != nil {
			return treeWorld{}, err
		}
		binds = append(binds, b)
	}
	// Overlap is judged on the canonical targets, where two stated
	// spellings of one directory — or a symlink into another grant's
	// subtree — meet.
	for i, a := range binds {
		for _, b := range binds[i+1:] {
			if a.Target == b.Target || strings.HasPrefix(a.Target, b.Target+"/") || strings.HasPrefix(b.Target, a.Target+"/") {
				return undeliverable("grants %s and %s overlap", a.Source, b.Source)
			}
		}
	}
	t.binds = binds
	return t, nil
}

// within reports whether the canonical path p lies strictly beneath
// the canonical directory dir — every path but "/" lies beneath "/".
func within(p, dir string) bool {
	if dir == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, dir+"/")
}

// resolveGrant validates one stated path and computes its bind.
func resolveGrant(root, p, what string) (bind, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return bind{}, fmt.Errorf("%w: %s %q is not a clean absolute path", ErrUndeliverable, what, p)
	}
	host, err := os.Stat(p)
	if err != nil {
		return bind{}, fmt.Errorf("%w: %s %s: %v", ErrUndeliverable, what, p, err)
	}
	if root == "" {
		target, err := filepath.EvalSymlinks(p)
		if err != nil {
			return bind{}, fmt.Errorf("%w: %s %s: %v", ErrUndeliverable, what, p, err)
		}
		return bind{Source: p, Target: target}, nil
	}
	// Every component of the target, walked from the tree down, must
	// be a real entry: a symlink anywhere on the way is a target the
	// bind and the pivoted process would resolve differently.
	dir := root
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		dir = filepath.Join(dir, seg)
		fi, err := os.Lstat(dir)
		if err != nil {
			return bind{}, fmt.Errorf("%w: %s %s has no target in the tree: %v", ErrUndeliverable, what, p, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return bind{}, fmt.Errorf("%w: %s %s passes through a symlink in the tree (%s)", ErrUndeliverable, what, p, strings.TrimPrefix(dir, root))
		}
		if dir == filepath.Join(root, p) && fi.IsDir() != host.IsDir() {
			return bind{}, fmt.Errorf("%w: %s %s is a %s on the host but a %s in the tree", ErrUndeliverable, what, p, kind(host.IsDir()), kind(fi.IsDir()))
		}
	}
	return bind{Source: p, Target: filepath.Join(root, p)}, nil
}

func kind(dir bool) string {
	if dir {
		return "directory"
	}
	return "file"
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
