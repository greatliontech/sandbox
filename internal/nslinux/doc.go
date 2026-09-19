// Package nslinux is the Linux mechanism layer beneath the sandbox
// backend: fail-loud verbs over the mount table, process hardening,
// and cgroup v2, composed into worlds by the backend above.
//
// Verbs, not policy: nothing here decides what a sandbox looks like.
// Each verb applies one kernel operation whole and reports failure
// rather than approximating — the backend's all-or-nothing delivery
// contract (docs/specs/sandbox.md) is only as strong as the verbs
// beneath it, so no verb has a best-effort path. Kernel preconditions
// are documented per verb; the package assumes the cgroup v2 unified
// hierarchy throughout.
//
// The layer began as a replica of greatliontech/container's create
// path (its nsenter, cgroups, security and seccomp files and the
// CLONE_INTO_CGROUP wiring) and is owned independently: the copies
// diverge by design — this one derives its shape from the sandbox
// contract (verbs that fail loud, no device or mask composition, a
// tier derived from what applied) while container keeps an OCI
// runtime's — but the kernel rules beneath them must not. Any
// kernel-rule fix found in either copy (locked mount flags on a
// read-only remount, cgroup placement under a delegated ancestry,
// the no-internal-process rule, CLONE_INTO_CGROUP semantics, and
// their kin) is applied to both; a contract-level rule (this layer
// closing swap under a memory bound) is each copy's own.
package nslinux
