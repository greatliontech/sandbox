# The Linux OS row has no implementation home

Lands: rows plan chunk 1

docs/specs/sandbox.md's ladder names a Linux `OS` row — Landlock
filesystem allowlist, seccomp network denial (Landlock ABI 4's TCP
restrictions supplementary, never the sole arm), `no_new_privs`,
rlimit bounds, static entrypoints only — for hosts without
unprivileged user namespaces. The Strong row is delivered whole,
and no artifact tracks the OS row's implementation;
the mechanism layer's package doc names the Landlock rung as a
difference by contract, not as a tracked deferral This issue is that
deferral: until it lands, a Linux host without unprivileged user
namespaces refuses instead of degrading to the OS tier the spec
offers.

Selection today falls past the row: a row with no mechanism to apply
is not one a host satisfies, so such a host reaches `Minimal`.

Consumer note: pb's REQ-plugin-sandboxed wording assumes the at-`/`
root view the Strong row presents; when an `OS`-tier row first
reaches pb, that spec's wording reconciles against `Root` as
world-restriction.
