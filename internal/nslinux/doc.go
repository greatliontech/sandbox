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
// The layer is an independently maintained replica of
// greatliontech/container's create path; the replication decision and
// its standing cost (kernel-rule fixes land in both copies) are
// recorded in docs/issues/linux-mechanism-replica.md.
package nslinux
