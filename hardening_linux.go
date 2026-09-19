//go:build linux

package sandbox

import (
	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/sys/unix"
)

// strongSeccompPolicy is the Strong row's syscall filter for the
// native ABI (a separate guard kills foreign-ABI calls outright,
// nslinux.LoadArchGuard): allow by default — a protoc plugin or a
// build tool must run unmodified — and deny, with EPERM, what would
// let the payload reshape the world the row delivered or reach past
// it. The denied families:
//
//   - the mount table (mount, umount2, the new mount API, pivot_root,
//     chroot): the pivoted read-only root is the world;
//   - namespace changes (unshare, setns);
//   - identity of the namespace (sethostname, setdomainname);
//   - kernel state no sandboxed process has business with: modules,
//     reboot, kexec, swap, clock setting (the time64 spellings
//     included), accounting, quotas, keyrings;
//   - observation and injection primitives (ptrace, perf_event_open,
//     bpf, userfaultfd, io_uring, process_vm_*).
//
// Names a build's architecture has no syscall for are left out of the
// filter (a syscall that does not exist needs no denial); every name
// must exist on at least one supported architecture, which
// TestPolicyNamesResolve pins. Thread creation (clone, clone3) stays
// allowed: a filter cannot inspect clone3's arguments, and denying it
// breaks every glibc program. A nested user namespace created that
// way regains a full bounding set inside itself; what still holds the
// world is what a fresh namespace cannot undo — the locked mount
// flags, the pivoted root with no descriptor out of it, and this
// filter, which every descendant inherits. personality stays allowed:
// common runtimes query it at startup.
func strongSeccompPolicy(native *arch.Info) seccomp.Policy {
	deny := func(names ...string) seccomp.SyscallGroup {
		var present []string
		for _, n := range names {
			if _, ok := native.SyscallNames[n]; ok {
				present = append(present, n)
			}
		}
		return seccomp.SyscallGroup{Action: seccomp.ActionErrno, Names: present}
	}
	var groups []seccomp.SyscallGroup
	for _, family := range strongDenied {
		if g := deny(family...); len(g.Names) > 0 {
			groups = append(groups, g)
		}
	}
	return seccomp.Policy{DefaultAction: seccomp.ActionAllow, Syscalls: groups}
}

// osSeccompPolicy is the OS row's syscall filter for the native ABI
// (the arch guard kills the foreign one, as on the Strong row): the
// Strong row's denials — a host that refused namespaces refuses
// unshare and mount to an unprivileged process anyway, and the
// filter says so on every host — and, where the network is not
// granted, the network denied at the socket: a socket of any family
// but the local one is refused with EAFNOSUPPORT, the local family
// staying open for the rendezvous. An ABI that also multiplexes the
// socket calls through socketcall (i386) carries the family in
// memory there, where no filter reads it: that route's socket and
// socketpair calls are refused whole, and the local family is
// reached by the direct calls, which the table has as well.
// Landlock's TCP rights, where the kernel has them, are applied
// beside this, never in its place: UDP and raw sockets are outside
// them (docs/specs/sandbox.md, the ladder).
func osSeccompPolicy(native *arch.Info, network bool) seccomp.Policy {
	policy := strongSeccompPolicy(native)
	if network {
		return policy
	}
	// The action's low sixteen bits carry the errno the caller sees.
	refused := seccomp.ActionErrno | seccomp.Action(unix.EAFNOSUPPORT)
	var names []seccomp.NameWithConditions
	for _, name := range []string{"socket", "socketpair"} {
		if _, ok := native.SyscallNames[name]; !ok {
			continue
		}
		names = append(names, seccomp.NameWithConditions{
			Name:       name,
			Conditions: seccomp.ArgumentConditions{{Argument: 0, Operation: seccomp.NotEqual, Value: unix.AF_UNIX}},
		})
	}
	if len(names) > 0 {
		policy.Syscalls = append(policy.Syscalls, seccomp.SyscallGroup{Action: refused, NamesWithCondtions: names})
	}
	if _, ok := native.SyscallNames["socketcall"]; ok {
		// socketcall's first argument is the call: SYS_SOCKET (1) and
		// SYS_SOCKETPAIR (8) of linux/net.h.
		const sysSocket, sysSocketpair = 1, 8
		policy.Syscalls = append(policy.Syscalls, seccomp.SyscallGroup{
			Action: refused,
			NamesWithCondtions: []seccomp.NameWithConditions{
				{Name: "socketcall", Conditions: seccomp.ArgumentConditions{{Argument: 0, Operation: seccomp.Equal, Value: sysSocket}}},
				{Name: "socketcall", Conditions: seccomp.ArgumentConditions{{Argument: 0, Operation: seccomp.Equal, Value: sysSocketpair}}},
			},
		})
	}
	return policy
}

// strongDenied is the Strong row's deny list by family, spelled once
// so a test can hold every name against the architecture tables.
var strongDenied = [][]string{
	{"mount", "umount2", "mount_setattr", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "pivot_root", "chroot"},
	{"unshare", "setns"},
	{"sethostname", "setdomainname"},
	{"init_module", "finit_module", "delete_module"},
	{"reboot", "kexec_load", "kexec_file_load"},
	{"swapon", "swapoff"},
	{"settimeofday", "clock_settime", "clock_settime64", "clock_adjtime", "clock_adjtime64", "adjtimex"},
	{"acct", "quotactl", "quotactl_fd"},
	{"add_key", "request_key", "keyctl"},
	{"ptrace", "perf_event_open", "bpf", "userfaultfd"},
	{"io_uring_setup", "io_uring_enter", "io_uring_register"},
	{"process_vm_readv", "process_vm_writev"},
}
