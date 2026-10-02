//go:build darwin

package sandbox

import (
	"debug/macho"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// substrate names the platform's execution substrate as Apple's
// system.sb admits it: the libraries every process on the platform
// maps, which an entrypoint may link against from inside a Root.
var substrate = []string{"/usr/lib/", "/System/Library/"}

// checkMachO holds an entrypoint under a Root to what the OS row can
// load without the image-absolute layout it does not present (docs/
// specs/sandbox.md, "Root is world-restriction"): a Mach-O image for
// this machine — a universal image serving it among others — whose
// libraries and run-path entries are the platform's execution
// substrate or relative to the image (@executable_path,
// @loader_path, @rpath), so that nothing it loads resolves at an
// image-absolute host path. A file that is no Mach-O image (a script
// names an interpreter the host would resolve) is refused.
func checkMachO(path string) error {
	f, err := openNative(path)
	if err != nil {
		return err
	}
	defer f.Close()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return fmt.Errorf("cannot read the image's libraries: %v", err)
	}
	for _, lib := range libs {
		if !imageRelative(lib) {
			return fmt.Errorf("dynamically linked against %s, an image-absolute path this row does not present: the tree's libraries are reached relative to the image or from the platform's substrate", lib)
		}
	}
	for _, l := range f.Loads {
		if rp, ok := l.(*macho.Rpath); ok && !imageRelative(rp.Path) {
			return fmt.Errorf("a run path %s, an image-absolute path this row does not present", rp.Path)
		}
	}
	return nil
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

// openNative opens the Mach-O image for this machine: the file
// itself, or the matching slice of a universal image.
func openNative(path string) (*macho.File, error) {
	want, ok := map[string]macho.Cpu{"arm64": macho.CpuArm64, "amd64": macho.CpuAmd64}[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("the native machine on %s is unknown to this row", runtime.GOARCH)
	}
	if fat, err := macho.OpenFat(path); err == nil {
		for _, a := range fat.Arches {
			if a.Cpu == want {
				return a.File, nil
			}
		}
		fat.Close()
		return nil, fmt.Errorf("a universal image serving no %s slice; this row runs %s only", runtime.GOARCH, runtime.GOARCH)
	}
	f, err := macho.Open(path)
	if err != nil {
		var fe *macho.FormatError
		if errors.As(err, &fe) {
			return nil, fmt.Errorf("cannot be read as a Mach-O image (%v); this row loads Mach-O entrypoints from the tree only", err)
		}
		return nil, err
	}
	if f.Cpu != want {
		f.Close()
		return nil, fmt.Errorf("built for %v; this row runs %s only", f.Cpu, runtime.GOARCH)
	}
	return f, nil
}
