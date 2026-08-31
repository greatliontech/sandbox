# The Linux OS row has no implementation home

Lands: strong-backend plan close-out (scheduling the row is the
user's call there)

docs/specs/sandbox.md's ladder names a Linux `OS` row — Landlock
filesystem allowlist, seccomp network denial (Landlock ABI 4's TCP
restrictions supplementary, never the sole arm), `no_new_privs`,
rlimit bounds, static entrypoints only — for hosts without
unprivileged user namespaces. The strong-backend plan delivers the
Strong row only, and no artifact tracks the OS row's implementation;
docs/issues/linux-mechanism-replica.md mentions "a Landlock rung
later" as rationale, not as a tracked deferral. This issue is that
deferral: until it lands, a Linux host without unprivileged user
namespaces refuses instead of degrading to the OS tier the spec
offers.
