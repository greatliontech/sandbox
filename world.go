//go:build linux || darwin

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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
	// hostCmd and hostWorkDir are the entrypoint and the working
	// directory as a row presenting the tree at its host path sees
	// them: inside the tree, the tree's root where no working
	// directory is stated — never the caller's; the stated paths
	// where there is no tree.
	hostCmd     string
	hostWorkDir string
	// runtime indexes the rendezvous directory's bind, -1 where none.
	runtime int
}

// checkSpelling holds the spec's paths and hostname to their forms
// before any row reads them: absolute paths, a hostname within the
// length a row could present.
func checkSpelling(spec Spec) error {
	undeliverable := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrUndeliverable}, a...)...)
	}
	if !filepath.IsAbs(spec.Exec) {
		return undeliverable("exec %q is not an absolute path", spec.Exec)
	}
	if spec.WorkDir != "" && !filepath.IsAbs(spec.WorkDir) {
		return undeliverable("workdir %q is not an absolute path", spec.WorkDir)
	}
	if len(spec.Hostname) > hostNameMax {
		return undeliverable("hostname %q is longer than %d bytes", spec.Hostname, hostNameMax)
	}
	return nil
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
	t := treeWorld{exec: spec.Exec, hostCmd: spec.Exec, hostWorkDir: spec.WorkDir, runtime: -1}
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
		t.hostCmd = filepath.Join(root, resolved)
		t.hostWorkDir = root
		if spec.WorkDir != "" {
			fi, _, err := statInTree(root, spec.WorkDir)
			if err != nil {
				return undeliverable("workdir %s is not in the tree: %v", spec.WorkDir, err)
			}
			if !fi.IsDir() {
				return undeliverable("workdir %s is not a directory in the tree", spec.WorkDir)
			}
			t.hostWorkDir = filepath.Join(root, spec.WorkDir)
		}
	}
	// The host entries the stated paths name, read once: a grant
	// whose host entry lies within the tree, or holds it — the host's
	// root over the tree's included — would make the tree writable
	// through the grant, which "never written" forbids; judged by
	// identity on the host entries before anything else is asked of
	// them, and again for overlap once the binds are resolved. The
	// paths are resolved before the mount table is read: resolving
	// walks through every directory on the way, which triggers an
	// automount there, and the mount it attaches must be in the table.
	type stated struct{ path, what, host string }
	var paths []stated
	for _, g := range spec.PathGrants {
		paths = append(paths, stated{path: g.Path, what: "grant"})
	}
	if spec.RuntimeDir != "" {
		paths = append(paths, stated{path: spec.RuntimeDir, what: "runtime dir"})
	}
	for i, p := range paths {
		if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path {
			continue // resolveGrant refuses it by name
		}
		if host, err := filepath.EvalSymlinks(p.path); err == nil {
			paths[i].host = host
		} // else resolveGrant refuses it by name
	}
	var m *mounts
	if len(paths) > 0 {
		var err error
		if m, err = readMounts(); err != nil {
			return undeliverable("the host's mounts: %v", err)
		}
	}
	hosts := map[string]named{}
	for _, p := range paths {
		if p.host == "" {
			continue
		}
		e, unread, err := hostEntry(m, p.host, true)
		if err != nil {
			return undeliverable("%s %s: %v", p.what, p.path, err)
		}
		if len(e) == 0 {
			return undeliverable("%s %s: cannot be read", p.what, p.path)
		}
		hosts[p.path] = named{e, unread}
	}
	if root != "" && len(paths) > 0 {
		tree, treeUnread, err := hostEntry(m, root, false)
		if err != nil {
			return undeliverable("root %s: %v", spec.Root, err)
		}
		for _, p := range paths {
			h, ok := hosts[p.path]
			if !ok {
				continue
			}
			switch rel, via := h.entry.judge(tree); rel {
			case sameEntry:
				return undeliverable("%s %s is the tree %s%s", p.what, p.path, spec.Root, via)
			case withinEntry:
				return undeliverable("%s %s lies within the tree %s%s", p.what, p.path, spec.Root, via)
			case holdsEntry:
				return undeliverable("%s %s holds the tree %s%s", p.what, p.path, spec.Root, via)
			}
			if len(h.unread) > 0 {
				return undeliverable("%s %s: its spelling %s, so what it names is not judged against the tree", p.what, p.path, h.unread[0])
			}
			if len(treeUnread) > 0 {
				return undeliverable("root %s: its spelling %s, so %s %s is not judged against it", spec.Root, treeUnread[0], p.what, p.path)
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
		if fi, err := os.Stat(spec.RuntimeDir); err == nil && !fi.IsDir() {
			return undeliverable("runtime dir %s is not a directory", spec.RuntimeDir)
		}
		t.runtime = len(binds)
		binds = append(binds, b)
	}
	// Overlap is judged by identity on the host entries and on the
	// entries they land on, where two stated spellings of one
	// directory — or a symlink into another grant's subtree — meet:
	// two intents over one host entry have no single delivery under
	// an allowlist, which unites their rights on the one inode, and
	// two over one entry of the tree none under binds.
	type placed struct {
		bind           bind
		source, target named
	}
	var placements []placed
	for i, b := range binds {
		what := "grant"
		if i == t.runtime {
			what = "runtime dir"
		}
		p := placed{bind: b}
		var ok bool
		if p.source, ok = hosts[b.Source]; !ok {
			return undeliverable("%s %s: cannot be read", what, b.Source)
		}
		p.target = p.source
		if root != "" {
			e, unread, err := hostEntry(m, b.Target, true)
			if err != nil {
				return undeliverable("%s %s: %v", what, b.Source, err)
			}
			p.target = named{e, unread}
		}
		placements = append(placements, p)
	}
	for i, a := range placements {
		for _, b := range placements[i+1:] {
			if rel, via := a.source.entry.judge(b.source.entry); rel != apart {
				return undeliverable("grants %s and %s overlap%s", a.bind.Source, b.bind.Source, via)
			}
			if rel, via := a.target.entry.judge(b.target.entry); rel != apart {
				return undeliverable("grants %s and %s overlap in the tree%s", a.bind.Source, b.bind.Source, via)
			}
			for _, n := range []struct {
				own   string
				other string
				where named
			}{{a.bind.Source, b.bind.Source, a.source}, {b.bind.Source, a.bind.Source, b.source}, {a.bind.Source, b.bind.Source, a.target}, {b.bind.Source, a.bind.Source, b.target}} {
				if len(n.where.unread) > 0 {
					return undeliverable("grant %s: its spelling %s, so what it names is not judged against grant %s", n.own, n.where.unread[0], n.other)
				}
			}
		}
	}
	t.binds = binds
	return t, nil
}

// identity is an entry's identity on the host: the device and inode
// every spelling of one entry shares — a bind mount's, a firmlink's,
// a case variant's, a symlink's. Containment and overlap are judged
// on it, never on spelling alone: a canonical spelling unifies
// symlinks and nothing else, and a bind mount has no canonical
// spelling at all.
type identity struct{ dev, ino uint64 }

// lineage is one spelling of an entry with the identities of the
// entry and of every directory above it along that spelling, the
// entry's own first: what a rule over a directory reaches.
type lineage struct {
	path string
	ids  []identity
}

// lineageOf reads the lineage of the canonical path p.
func lineageOf(p string) (lineage, error) {
	l := lineage{path: p}
	for {
		fi, err := os.Stat(p)
		if err != nil {
			return lineage{}, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return lineage{}, fmt.Errorf("%s: no inode", p)
		}
		l.ids = append(l.ids, identity{dev: uint64(st.Dev), ino: st.Ino})
		if p == "/" {
			return l, nil
		}
		p = filepath.Dir(p)
	}
}

// entry is a host entry as a path rule reaches it: one lineage for
// each spelling under which the entry, or what lies beneath it, can
// be named — the entry's canonical path; its origin's spellings,
// where a mount grafts a subtree of one filesystem onto another path
// (a bind mount of a directory) or a firmlink does, so that a rule
// over the origin's ancestor reaches the entry too; and, where the
// mounts beneath count, the spellings of every mount beneath it, a
// rule over a directory reaching every mount beneath. The first
// lineage is the entry's own canonical spelling.
type entry []lineage

// hostEntry reads the entry of the canonical path p, with the mounts
// beneath it where beneath is set — a grant's, which a rule covers
// whole; never the tree's, whose own mounts are the caller's shape.
// A spelling the caller cannot read — an origin's, a mount's beneath
// — is unread where a directory the caller owns bars it: the
// payload, running as the caller, may open that directory from
// within a grant, so what the spelling names is unjudged, which a
// judgement that finds nothing else must refuse. One barred by
// another's directory, or naming nothing, is left out: the payload
// cannot reach it either.
func hostEntry(m *mounts, p string, beneath bool) (e entry, unread []string, err error) {
	if e, unread, err = spellingsOf(m, p); err != nil {
		return nil, nil, err
	}
	if beneath {
		for _, mb := range m.beneath(p) {
			spellings := append([]string{mb.point}, mb.origins...)
			if mb.err != nil {
				if barred(mb.point, mb.err) {
					unread = append(unread, unreadable(mb.point, mb.err))
				}
				spellings = nil
			}
			for _, s := range spellings {
				l, err := lineageOf(s)
				if err != nil {
					if barred(s, err) {
						unread = append(unread, unreadable(s, err))
					}
					continue
				}
				e = append(e, l)
			}
		}
	}
	slices.Sort(unread)
	return e, unread, nil
}

// unreadable spells an unread spelling with why it is: "<path>
// cannot be read (<reason>)".
func unreadable(s string, err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Sprintf("%s cannot be read (%v)", s, err)
}

// errUntriggered is an automount point not yet triggered: what a
// lookup there would mount is the map's to say, and the resolution
// fires none, so the entry is unjudged.
var errUntriggered = errors.New("an automount not yet triggered, which the resolution does not fire")

// mountBeneath is a mount beneath a directory: its mount point and
// the spellings its origin has, or the failure to read them.
type mountBeneath struct {
	point   string
	origins []string
	err     error
}

// spellingsOf reads the lineages of the canonical path p and of its
// origin spellings, p's own first, p itself readable or the error
// its own; an origin the caller cannot read is unread where a
// directory the caller owns bars it (barred), left out otherwise;
// p an automount point not yet triggered is unread as such.
func spellingsOf(m *mounts, p string) (e entry, unread []string, err error) {
	l, err := lineageOf(p)
	if err != nil {
		return nil, nil, err
	}
	e = entry{l}
	if m.untriggered(p) {
		// Its origins are not asked for: reading them would open the
		// point, which is what fires it.
		return e, []string{unreadable(p, errUntriggered)}, nil
	}
	origins, err := m.origins(p)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range origins {
		l, err := lineageOf(s)
		if err != nil {
			if barred(s, err) {
				unread = append(unread, unreadable(s, err))
			}
			continue
		}
		e = append(e, l)
	}
	return e, unread, nil
}

// barred reports whether the spelling s, unreadable for err, is
// barred by a directory the caller owns — the deepest one on the way
// that can still be reached, which the payload, running as the
// caller, could open — rather than naming nothing or lying behind a
// directory another user closed, which stays closed to the payload.
// A failure of another kind, on the spelling or on the way to it, is
// a spelling that cannot be judged.
func barred(s string, err error) bool {
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENAMETOOLONG):
		return false
	case !errors.Is(err, fs.ErrPermission):
		return true
	}
	dir := "/"
	for _, seg := range strings.Split(strings.TrimPrefix(s, "/"), "/") {
		next := filepath.Join(dir, seg)
		if _, err := os.Lstat(next); err != nil {
			if !errors.Is(err, fs.ErrPermission) {
				return true
			}
			break
		}
		dir = next
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return true
	}
	// Ownership is the effective user's: the one permission checks
	// are made for, and the one a chmod is allowed to.
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) == os.Geteuid()
}

// named is what a stated path names: its entry, and the mounts
// beneath it the caller could not read under any spelling.
type named struct {
	entry  entry
	unread []string
}

// within reports whether the canonical path p lies strictly beneath
// the canonical directory dir — every path but "/" lies beneath "/".
func within(p, dir string) bool {
	if dir == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, dir+"/")
}

// relation is how one entry stands to another.
type relation int

const (
	apart       relation = iota
	sameEntry            // one entry
	holdsEntry           // a directory strictly above the other
	withinEntry          // strictly beneath the other
)

// judge reports how e stands to o, and the spellings it found the
// relation through where they are not the entries' own: "" where
// both are, " through <e's> (<o's>)" otherwise.
func (e entry) judge(o entry) (relation, string) {
	for _, l := range e {
		for _, k := range o {
			var rel relation
			switch {
			case l.ids[0] == k.ids[0]:
				rel = sameEntry
			case slices.Contains(k.ids[1:], l.ids[0]):
				rel = holdsEntry
			case slices.Contains(l.ids[1:], k.ids[0]):
				rel = withinEntry
			default:
				continue
			}
			via := ""
			if l.path != e[0].path || k.path != o[0].path {
				via = fmt.Sprintf(" through %s (%s)", l.path, k.path)
			}
			return rel, via
		}
	}
	return apart, ""
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
	// A file granted under a Root with another name on the host could
	// be the tree's own file under that name — a hard link into the
	// tree, which no path can see — so a file grant has one name.
	if !host.IsDir() {
		if st, ok := host.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			return bind{}, fmt.Errorf("%w: %s %s has %d names on the host; a file granted under a Root has one", ErrUndeliverable, what, p, st.Nlink)
		}
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
