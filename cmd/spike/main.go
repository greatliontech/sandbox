// Command spike runs a process inside a sandbox to demonstrate the backend.
//
//	go run ./cmd/spike
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/greatliontech/sandbox"
)

func main() {
	sb, err := sandbox.New(sandbox.Spec{
		Exec:     "/bin/sh",
		Args:     []string{"-c", `echo "pid=$$ uid=$(id -u) host=$(cat /proc/sys/kernel/hostname)"`},
		Hostname: "spikebox",
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "new:", err)
		os.Exit(1)
	}
	if err := sb.Start(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	es, err := sb.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wait:", err)
		os.Exit(1)
	}
	fmt.Printf("--- exited code=%d tier=%s ---\n", es.Code, sb.Tier())
}
