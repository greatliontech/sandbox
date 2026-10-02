//go:build linux

package nslinux

import (
	"testing"
)

func TestLastCapProbesKernel(t *testing.T) {
	last, err := lastCap()
	if err != nil {
		t.Fatal(err)
	}
	// CAP_AUDIT_READ (37) closed out the 3.x additions; anything a
	// supported kernel reports is at least that.
	if last < 37 || last > 63 {
		t.Errorf("lastCap = %d, want within [37, 63]", last)
	}
}
