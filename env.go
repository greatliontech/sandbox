package sandbox

import (
	"os"
	"strings"
)

// payloadEnv is the payload's environment: the stated one; where
// none is stated, empty under a Root — a restricted world carries
// nothing of the host unstated (docs/specs/sandbox.md, "Root is
// world-restriction") — and the host's own otherwise.
func payloadEnv(spec Spec) []string {
	switch {
	case spec.Env != nil:
		return spec.Env
	case spec.Root != "":
		return []string{}
	}
	return hostEnv()
}

// hostEnv is the caller's environment without this package's re-exec
// markers, which name descriptors only the init child holds.
func hostEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "_SANDBOX_") {
			env = append(env, kv)
		}
	}
	return env
}
