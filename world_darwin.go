//go:build darwin

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mounts is the caller's mount table, read once per resolution from
// the kernel's listing of mounted filesystems: what tells the mounts
// beneath a directory. The spellings a path has through its origin
// are the kernel's own to tell here: a firmlink grafts a directory
// of the data volume onto the system volume's namespace, and the
// kernel spells a path under one both ways.
type mounts struct {
	points []string
	types  map[string]string // by mount point
}

func readMounts() (*mounts, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	buf := make([]unix.Statfs_t, n)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	m := &mounts{types: map[string]string{}}
	for _, fs := range buf[:n] {
		point := unix.ByteSliceToString(fs.Mntonname[:])
		m.points = append(m.points, point)
		m.types[point] = unix.ByteSliceToString(fs.Fstypename[:])
	}
	return m, nil
}

// untriggered reports whether the canonical path p is an automount
// point not yet triggered: the mount a lookup there replaces with
// what the map says.
func (m *mounts) untriggered(p string) bool {
	return m.types[p] == "autofs"
}

// beneath lists the mounts strictly beneath the canonical directory
// dir, each with its origin spellings as the kernel tells them, or
// the failure to read them.
func (m *mounts) beneath(dir string) []mountBeneath {
	var out []mountBeneath
	for _, p := range m.points {
		if within(p, dir) {
			mb := mountBeneath{point: p}
			if m.untriggered(p) {
				mb.err = errUntriggered
			} else {
				mb.origins, mb.err = m.origins(p)
			}
			out = append(out, mb)
		}
	}
	return out
}

// origins lists the spellings the canonical path p has besides its
// own: the kernel's spelling of it (symlinks and firmlinks resolved,
// the filesystem's case) and the spelling with no firmlink crossed,
// under which a path on the data volume is reached from the volume's
// own mount point.
func (m *mounts) origins(p string) ([]string, error) {
	var out []string
	for _, cmd := range []int{unix.F_GETPATH, unix.F_GETPATH_NOFIRMLINK} {
		s, err := fcntlPath(p, cmd)
		if err != nil {
			return nil, err
		}
		if s != p && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// fcntlPath reads a path of an existing entry back from the kernel
// through the fcntl command cmd (F_GETPATH, F_GETPATH_NOFIRMLINK),
// from a descriptor opened for no access at all (O_EVTONLY) and
// without blocking (a FIFO opened for reading would wait for a
// writer). An entry that cannot be opened at all — a unix socket —
// is spelled as its directory is, with its own name as the
// directory lists it.
func fcntlPath(path string, cmd int) (string, error) {
	fd, err := unix.Open(path, unix.O_EVTONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EOPNOTSUPP) && path != "/" {
		dir, err := fcntlPath(filepath.Dir(path), cmd)
		if err != nil {
			return "", err
		}
		name, err := listedName(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, name), nil
	}
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	var buf [unix.PathMax]byte
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return "", errno
	}
	return unix.ByteSliceToString(buf[:]), nil
}

// listedName is name as the directory dir lists it: the entry's own
// case on a volume that folds case.
func listedName(dir, name string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.Name() == name {
			return name, nil
		}
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name(), name) {
			return e.Name(), nil
		}
	}
	return "", &os.PathError{Op: "lstat", Path: filepath.Join(dir, name), Err: unix.ENOENT}
}
