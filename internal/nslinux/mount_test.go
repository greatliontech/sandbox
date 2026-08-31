//go:build linux

package nslinux

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLockedFlagsMapsEachLockableAttribute(t *testing.T) {
	cases := []struct {
		name   string
		statfs int64
		want   uintptr
	}{
		{"none", 0, 0},
		{"nosuid", unix.ST_NOSUID, unix.MS_NOSUID},
		{"nodev", unix.ST_NODEV, unix.MS_NODEV},
		{"noexec", unix.ST_NOEXEC, unix.MS_NOEXEC},
		{"noatime", unix.ST_NOATIME, unix.MS_NOATIME},
		{"nodiratime", unix.ST_NODIRATIME, unix.MS_NODIRATIME},
		{"relatime", unix.ST_RELATIME, unix.MS_RELATIME},
		{
			"all combined",
			unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC | unix.ST_NOATIME | unix.ST_NODIRATIME | unix.ST_RELATIME,
			unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME | unix.MS_NODIRATIME | unix.MS_RELATIME,
		},
		// Read-only is not a locked *attribute* — the remount sets
		// MS_RDONLY itself — and statfs exposes no strictatime bit,
		// so neither may leak into the repeated set.
		{"rdonly ignored", unix.ST_RDONLY, 0},
		{"rdonly plus nosuid", unix.ST_RDONLY | unix.ST_NOSUID, unix.MS_NOSUID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockedFlags(tc.statfs); got != tc.want {
				t.Errorf("lockedFlags(%#x) = %#x, want %#x", tc.statfs, got, tc.want)
			}
		})
	}
}

func TestLockedMountFlagsFailsLoudOnStatfsError(t *testing.T) {
	// A path that cannot be statfs'd cannot have its locked flags
	// repeated; proceeding would trade the real diagnostic for a
	// confusing kernel EPERM, so the verb refuses instead.
	if _, err := lockedMountFlags("/nonexistent/nslinux-test"); err == nil {
		t.Error("want error when statfs fails")
	}
}
