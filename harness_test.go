package sandbox

import (
	"context"
	"strings"
	"testing"
)

// facts parses a payload's "key=value" lines.
func facts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// run starts the spec and waits for it, failing the test on either.
func run(t *testing.T, spec Spec) (Sandbox, ExitStatus) {
	t.Helper()
	sb, err := New(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st, err := sb.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	return sb, st
}
