//go:build !linux && !windows && !darwin

package sandbox

import "context"

// newSandbox is the fallback for platforms with no sandbox backend.
func newSandbox(spec Spec) (Sandbox, error) {
	return nil, ErrUnsupported
}

func reach(context.Context, Spec) (Isolation, []string, error) { return None, nil, ErrUnsupported }
