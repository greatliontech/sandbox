//go:build darwin

package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReadingsAgree pins the kernel's two readings of one process
// against each other and against what the process holds — the
// layout each is read by: the resource-usage reading's resident
// size and CPU times agree with the task-info reading's, its
// footprint counts the memory this process touched, and the task
// info counts this process's threads.
func TestReadingsAgree(t *testing.T) {
	const touched = 64 << 20
	buf := make([]byte, touched)
	for i := range buf {
		buf[i] = byte(i)
	}
	ru, err := rusage(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ti, err := taskInfo(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(buf)
	if ru.footprint < touched {
		t.Errorf("footprint %d, want at least the %d bytes touched", ru.footprint, touched)
	}
	if ru.resident == 0 || ti.resident == 0 || ru.resident > 2*ti.resident || ti.resident > 2*ru.resident {
		t.Errorf("resident sizes %d (rusage) and %d (task info) disagree", ru.resident, ti.resident)
	}
	a, b := ru.user+ru.system, ti.user+ti.system
	if a == 0 || b == 0 || a-b > 500*time.Millisecond || b-a > 500*time.Millisecond {
		t.Errorf("CPU times %v (rusage) and %v (task info) disagree", a, b)
	}
	if ti.threads == 0 {
		t.Error("task info counts no threads")
	}
	// The footprint is told from the resident size: a file mapped
	// read-only and touched throughout raises the resident size by
	// its length and the footprint hardly at all, file-backed pages
	// being no part of what a process costs.
	const mapped = 64 << 20
	path := filepath.Join(t.TempDir(), "mapped")
	if err := os.WriteFile(path, make([]byte, mapped), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The runtime's own pages settled first, so that neither reading
	// moves by what the collector returns between them.
	debug.FreeOSMemory()
	before, err := rusage(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	data, err := unix.Mmap(int(f.Fd()), 0, mapped, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(data)
	var sum byte
	for i := 0; i < len(data); i += 4096 {
		sum += data[i]
	}
	after, err := rusage(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(sum)
	if after.resident < before.resident+mapped/2 {
		t.Errorf("resident size %d then %d: the mapped file's pages not counted", before.resident, after.resident)
	}
	if after.footprint > before.footprint+mapped/4 {
		t.Errorf("footprint %d then %d: the mapped file's pages counted as the process's cost", before.footprint, after.footprint)
	}
}
