//go:build linux

package nslinux

import (
	"strings"
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

// mountSubtree lists the topmost mount at path and its descendants by
// parent id, shallowest first, decoding mountinfo's octal escapes;
// mounts an earlier bind at the same path shadows, and mounts beside
// the subtree, are left out.
func TestMountSubtree(t *testing.T) {
	info := []byte(strings.Join([]string{
		"22 1 0:21 / /proc rw - proc proc rw",
		"40 1 0:30 / /dev rw - devtmpfs devtmpfs rw",
		"41 40 0:31 / /dev/shm rw - tmpfs tmpfs rw",
		"43 1 0:33 / /devices rw - tmpfs tmpfs rw",
		"50 1 0:30 / /dev rw - devtmpfs devtmpfs rw",
		"51 50 0:32 / /dev/pts rw - devpts devpts rw",
		"52 50 0:34 / /dev/with\\040space rw - tmpfs tmpfs rw",
		"53 52 0:35 / /dev/with\\040space/deep rw - tmpfs tmpfs rw",
	}, "\n"))
	got := mountSubtree(info, "/dev/")
	want := []string{"/dev", "/dev/pts", "/dev/with space", "/dev/with space/deep"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("mountSubtree = %v, want %v", got, want)
	}
	if got := mountSubtree(info, "/nowhere"); len(got) != 0 {
		t.Fatalf("mountSubtree(/nowhere) = %v", got)
	}
}

// A listing with no mount at path refuses instead of covering nothing.
func TestReadOnlySubtreeRefusesUnlistedPath(t *testing.T) {
	info := []byte("40 1 0:30 / /dev rw - devtmpfs devtmpfs rw\n")
	if got, err := readOnlySubtree(info, "/dev"); err != nil || len(got) != 1 {
		t.Fatalf("listed path: %v %v", got, err)
	}
	if _, err := readOnlySubtree(info, "/link-to-dev"); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("unlisted path: %v", err)
	}
}
