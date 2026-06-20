//go:build !linux && !windows && !darwin

package sandbox

// newSandbox is the fallback for platforms with no sandbox backend.
func newSandbox(spec Spec) (Sandbox, error) {
	return nil, ErrUnsupported
}
