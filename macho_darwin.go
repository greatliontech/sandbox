//go:build darwin

package sandbox

import (
	"bytes"
	"debug/macho"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
)

// substrate names the platform's execution substrate as Apple's
// system.sb admits it: the libraries every process on the platform
// maps, which an entrypoint may link against from inside a Root.
var substrate = []string{"/usr/lib/", "/System/Library/"}

// checkMachO holds an entrypoint under a Root to what the OS row can
// load without the image-absolute layout it does not present (docs/
// specs/sandbox.md, "Root is world-restriction"): an executable
// Mach-O image for this machine — a universal image serving it among
// others — whose dynamic linker, libraries (loaded, weakly, lazily,
// upward or re-exported) and run-path entries are the platform's
// execution substrate or relative to the image (@executable_path,
// @loader_path, @rpath), and which sets no loader environment, so
// that nothing it loads resolves at an image-absolute host path. A
// file that is no Mach-O image (a script names an interpreter the
// host would resolve) is refused.
func checkMachO(path string) error {
	f, closer, err := openNative(path)
	if err != nil {
		return err
	}
	defer closer.Close()
	if f.Type != macho.TypeExec {
		return fmt.Errorf("a Mach-O image of type %v, not an executable", f.Type)
	}
	for _, l := range f.Loads {
		name, what, ok := loadPath(f, l)
		if !ok {
			continue
		}
		if what == "a loader environment" {
			return fmt.Errorf("sets %s (%s), which this row does not honour", what, name)
		}
		if !imageRelative(name) {
			return fmt.Errorf("%s %s, an image-absolute path this row does not present: the tree's libraries are reached relative to the image or from the platform's substrate", what, name)
		}
	}
	return nil
}

// The load commands naming what the loader resolves, each a
// dylib_command or a string command: the name's offset at byte 8.
const (
	loadDylinker    = 0xe
	loadLazyDylib   = 0x20
	loadDyldEnv     = 0x27
	loadWeakDylib   = 0x80000018
	loadReexport    = 0x8000001f
	loadUpwardDylib = 0x80000023
)

// loadPath reads a load command's path, where it has one: the
// library a dylib command names, a run path, the dynamic linker, a
// loader environment entry.
func loadPath(f *macho.File, l macho.Load) (name, what string, ok bool) {
	switch c := l.(type) {
	case *macho.Dylib:
		return c.Name, "dynamically linked against", true
	case *macho.Rpath:
		return c.Path, "a run path", true
	}
	raw := l.Raw()
	if len(raw) < 12 {
		return "", "", false
	}
	cmd := f.ByteOrder.Uint32(raw[0:4])
	switch cmd {
	case loadWeakDylib:
		what = "weakly linked against"
	case loadReexport:
		what = "re-exporting"
	case loadLazyDylib:
		what = "lazily linked against"
	case loadUpwardDylib:
		what = "linked upward against"
	case loadDylinker:
		what = "loaded by"
	case loadDyldEnv:
		what = "a loader environment"
	default:
		return "", "", false
	}
	off := f.ByteOrder.Uint32(raw[8:12])
	if int(off) >= len(raw) {
		return "", what, true
	}
	name = string(bytes.TrimRight(raw[off:], "\x00"))
	if i := bytes.IndexByte([]byte(name), 0); i >= 0 {
		name = name[:i]
	}
	return name, what, true
}

// imageRelative reports whether a library or run path resolves
// relative to the image or within the platform's substrate.
func imageRelative(p string) bool {
	for _, prefix := range []string{"@executable_path", "@loader_path", "@rpath"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	for _, prefix := range substrate {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// openNative opens the Mach-O image for this machine — the machine
// being the one this binary runs for — with the closer that releases
// the file: the file itself, or the matching slice of a universal
// image, whose closer is the universal file's.
func openNative(path string) (*macho.File, io.Closer, error) {
	want, ok := map[string]macho.Cpu{"arm64": macho.CpuArm64, "amd64": macho.CpuAmd64}[runtime.GOARCH]
	if !ok {
		return nil, nil, fmt.Errorf("the native machine on %s is unknown to this row", runtime.GOARCH)
	}
	if fat, err := macho.OpenFat(path); err == nil {
		for _, a := range fat.Arches {
			if a.Cpu == want {
				return a.File, fat, nil
			}
		}
		fat.Close()
		return nil, nil, fmt.Errorf("a universal image serving no %s slice; this row runs %s only", runtime.GOARCH, runtime.GOARCH)
	}
	f, err := macho.Open(path)
	if err != nil {
		var fe *macho.FormatError
		if errors.As(err, &fe) {
			return nil, nil, fmt.Errorf("cannot be read as a Mach-O image (%v); this row loads Mach-O entrypoints from the tree only", err)
		}
		return nil, nil, err
	}
	if f.Cpu != want {
		f.Close()
		return nil, nil, fmt.Errorf("built for %v; this row runs %s only", f.Cpu, runtime.GOARCH)
	}
	return f, f, nil
}
