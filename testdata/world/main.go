//go:build ignore

// Command world is the Strong-world probe the live tests exec inside a
// sandboxed tree: it reports what the process can see and touch, one
// "key=value" line per fact, so each contract clause has one line to
// assert on. Arguments: the read-only grant, the read-write grant, and
// the rendezvous directory to probe (each may be empty).
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	ro, rw, run := arg(1), arg(2), arg(3)

	cwd, _ := os.Getwd()
	fmt.Println("cwd=" + cwd)
	fmt.Printf("env=%d\n", len(os.Environ()))

	entries, _ := os.ReadDir("/")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	fmt.Println("root=" + strings.Join(names, ","))

	host, _ := os.ReadFile("/proc/sys/kernel/hostname")
	fmt.Printf("proc-hostname=%q\n", strings.TrimSpace(string(host)))

	fmt.Printf("write-root-err=%v\n", os.WriteFile("/probe", []byte("x"), 0o644) != nil)
	fmt.Printf("mkdir-root-err=%v\n", os.Mkdir("/probe-dir", 0o755) != nil)

	if ro != "" {
		b, err := os.ReadFile(ro + "/marker")
		fmt.Printf("ro-read=%q\n", string(b))
		fmt.Printf("ro-read-err=%v\n", err != nil)
		fmt.Printf("ro-write-err=%v\n", os.WriteFile(ro+"/probe", []byte("x"), 0o644) != nil)
	}
	if rw != "" {
		fmt.Printf("rw-write-err=%v\n", os.WriteFile(rw+"/probe", []byte("x"), 0o644) != nil)
	}
	if run != "" {
		fmt.Printf("run-write-err=%v\n", os.WriteFile(run+"/sock", []byte("x"), 0o644) != nil)
	}
}

func arg(i int) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return ""
}
