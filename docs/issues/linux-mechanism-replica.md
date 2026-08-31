# The Linux mechanism layer replicates container's create path

Lands: sandbox's first tagged release whose Linux backend delivers the
Strong row of docs/specs/sandbox.md whole (checkable against this
repo's tags)

The internal Linux mechanism layer — namespaces at clone, pivot plus
read-only remount repeating locked mount flags, capability drop,
seccomp, no_new_privs, rlimits, cgroup placement via the delegated
subtree and CLONE_INTO_CGROUP — is seeded from greatliontech/container's
create path at commit 866eb725dc6be9acb1ac36fd66ce8152280e71aa —
nsenter.go, cgroups.go, security.go, seccomp.go, and the
CLONE_INTO_CGROUP wiring in container.go — and maintained
independently.

Replication is a decision, not drift: it keeps sandbox's internal API
free to find its shape under sandbox's own contract (tier derived from
what applied, fail-loud verbs, no device/mask composition, a Landlock
rung later) without a cross-repo dependency freezing it mid-derivation.
The copies are expected to diverge; the kernel rules beneath them must
not. The standing cost: any kernel-rule fix found in either copy MUST
be applied to both. The twin record is container's
docs/issues/sandbox-create-path-replica.md.

At the trigger, judge consolidation against the stabilized API: extract
a shared exported layer container can rebase onto, or record that
independent ownership is the end state. Both outcomes resolve this
issue.
