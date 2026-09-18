//go:build amd64

// Command abiswitch is a native amd64 program that, after announcing
// itself through the native ABI, issues one system call through the
// i386 ABI (int 0x80). Under the Strong row's arch guard that call is
// its last: the process dies by SIGSYS.
package main

import (
	"fmt"
	"os"
)

func int80getpid() int32

func main() {
	fmt.Println("alive")
	os.Stdout.Sync()
	fmt.Println("i386 getpid:", int80getpid())
}
