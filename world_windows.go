package sandbox

import (
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// The windows row's reading of the host: an entry's identity is its
// volume's serial and its file index on it, which every spelling of
// one entry shares — a case variant's, a short name's, a junction's;
// ownership the process token's user; a grant under a Root lands at
// its host path, the tree never presented at another; and the
// platform's own lookup resolves a path in the tree, a link in it
// followed on the host.

// mounts is the host's mount table as the judgement reads it: none.
// The platform grafts a volume onto a directory and a junction onto
// a path, and a lookup through either reaches the entry under the
// target's own identity, which the lineage of a canonical path (the
// kernel's final path, every junction and link resolved) walks; a
// rule over a directory — an inheriting entry in its descriptor —
// reaches no mounted volume or junction target beneath it, so none
// counts beneath a grant, and the platform mounts nothing on lookup.
type mounts struct{}

func readMounts() (*mounts, error) { return &mounts{}, nil }

func (m *mounts) untriggered(string) bool { return false }

func (m *mounts) beneath(string) []mountBeneath { return nil }

func (m *mounts) origins(string) ([]string, error) { return nil, nil }

// canonical is the path an entry stands at, every junction and
// symbolic link on the way resolved, as the kernel spells it (the
// final path by handle). The standard library's resolution is not
// it: a junction — a mount point, which the os package reports as
// neither a directory nor a link — is left standing by
// filepath.EvalSymlinks, and refused as no directory on the way to
// anything beneath.
func canonical(p string) (string, error) {
	h, err := openForNothing(p)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", &os.PathError{Op: "readlink", Path: p, Err: err}
		}
		if int(n) < len(buf) {
			// The kernel's spelling carries the long-path prefix: a
			// drive's path with "\\?\", a share's with "\\?\UNC\"
			// for the "\\" a share is spelled with; a volume with no
			// letter is spelled by its GUID, a form only the prefix
			// opens, so it keeps it.
			s := windows.UTF16ToString(buf[:n])
			if rest, ok := strings.CutPrefix(s, `\\?\UNC\`); ok {
				return `\\` + rest, nil
			}
			if rest, ok := strings.CutPrefix(s, `\\?\`); ok && len(rest) > 1 && rest[1] == ':' {
				return rest, nil
			}
			return s, nil
		}
		buf = make([]uint16, n+1)
	}
}

// openForNothing opens an entry for no access at all, a directory
// included (FILE_FLAG_BACKUP_SEMANTICS), every link on the way
// followed.
func openForNothing(p string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: p, Err: err}
	}
	return h, nil
}

// identityOf reads an entry's identity through a handle opened for
// no access, a directory included (FILE_FLAG_BACKUP_SEMANTICS).
func identityOf(p string) (identity, error) {
	info, err := fileInformation(p)
	if err != nil {
		return identity{}, err
	}
	return identity{dev: uint64(info.VolumeSerialNumber), ino: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)}, nil
}

// fileLinks counts the names a file has on the host.
func fileLinks(p string) (uint64, error) {
	info, err := fileInformation(p)
	if err != nil {
		return 0, err
	}
	return uint64(info.NumberOfLinks), nil
}

func fileInformation(p string) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	h, err := openForNothing(p)
	if err != nil {
		return info, err
	}
	defer windows.CloseHandle(h)
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return info, &os.PathError{Op: "stat", Path: p, Err: err}
	}
	return info, nil
}

// ownsEntry reports whether the process token's user owns the entry:
// the one a change of its permissions is allowed to.
func ownsEntry(p string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, &os.PathError{Op: "stat", Path: p, Err: err}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); err != nil {
		return false, err
	}
	defer t.Close()
	user, err := t.GetTokenUser()
	if err != nil {
		return false, err
	}
	return owner.Equals(user.User.Sid), nil
}

// grantsLandInTree: a grant under a Root lands at its host path,
// which the row grants to the run's identity where it stands; the
// tree is never presented at another path, so a host path has no
// spelling inside it and needs no entry there (docs/specs/sandbox.md,
// the ladder's windows row).
const grantsLandInTree = false

// resolveInTree resolves a tree-absolute path as the platform's
// process will: the path cleaned as the platform cleans one (".."
// applied before any lookup, clamped at the tree), joined to the
// tree and looked up on the host, a link on the way followed to
// where it leads — on the host, the tree being no root to the
// process — and refused where that is out of the tree, which the
// process could not read. The resolved path is the cleaned one: the
// platform follows the links itself.
func resolveInTree(root, p string) (os.FileInfo, string, error) {
	rel := path.Clean("/" + filepath.ToSlash(p))
	host := filepath.Join(root, filepath.FromSlash(rel))
	final, err := canonical(host)
	if err != nil {
		return nil, "", err
	}
	fi, err := os.Stat(final)
	if err != nil {
		return nil, "", err
	}
	tree, err := lineageOf(root)
	if err != nil {
		return nil, "", err
	}
	l, err := lineageOf(final)
	if err != nil {
		return nil, "", err
	}
	if how, _ := (entry{tree}).judge(entry{l}); how != sameEntry && how != holdsEntry {
		return nil, "", fmt.Errorf("%s leads out of the tree, to %s", p, final)
	}
	return fi, rel, nil
}

// checkPE holds an entrypoint to a PE executable image, which the
// platform's loader runs: a library, a script or a file of another
// format is refused before anything runs.
func checkPE(p string) error {
	r, err := os.Open(p)
	if err != nil {
		return err
	}
	defer r.Close()
	// Whatever the reading of an opened file finds wrong — a header
	// of another format, a file too short for one — is no PE image.
	f, err := pe.NewFile(r)
	if err != nil {
		return fmt.Errorf("not a PE image: %v", err)
	}
	defer f.Close()
	const executableImage, library = 0x0002, 0x2000 // IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_DLL
	switch {
	case f.Characteristics&library != 0:
		return errors.New("a PE library, not an executable image")
	case f.Characteristics&executableImage == 0:
		return errors.New("a PE file that is no executable image")
	}
	return nil
}
