# The code does not yet conform to the contract

Lands: strong-backend plan chunk 5 (row selection and tier derivation close the remaining gaps)

docs/specs/sandbox.md pins the contract ahead of the code. The known
nonconformities, so none is silent:

- `Tier()` asserts `Strong` unconditionally while the Strong row's
  cgroup arm is unimplemented (its pivot, capability drop, seccomp,
  and no_new_privs arms are delivered) — the spec requires tier
  derived from the row that fully applied.
- The `MinTier` gate compares against a constant maximum, so it can
  never refuse: "fails closed before exec" currently fails open, and
  no host probes exist to select a row.
- `Spec.Root` is delivered on the Strong row (pivoted read-only,
  grants and rendezvous bound, entrypoint from the tree) with
  composition failures refusing `Start`; rows without mount
  namespaces have no `Root` handling yet.
- Bounds are rlimits only, and no surface reports which accounting
  enforced them ("a reported fact of the run" has no reporter; `Stats`
  is empty).
- `Spec.Hostname`'s doc says "where the platform supports it" — the
  best-effort arm the delivery contract forbids; a row that cannot
  present a stated hostname must refuse.
- `ErrUndeliverable` exists and covers the world's refusals (a Root
  that is no directory, grants without a target); the row-selection
  refusals still route through plain errors until chunk 5, and a
  row's own application failure inside the init (a seccomp filter
  that will not load) currently rides the same sentinel as an
  undeliverable intent — chunk 5's error routing separates "the
  host cannot do what you asked" from "the row failed to apply".
- Cleanup reaches the direct child only, on both triggers
  (`CommandContext` kill, `Pdeathsig`); the contract's
  cancellation-time tree, cgroup, and group kills, and any kernel-side
  tie beyond the parent-death signal, are undelivered.

Consumer note: pb's REQ-plugin-sandboxed wording assumes the
at-`/` root view the Strong row presents; when an `OS`-tier row first
reaches pb, that spec's wording reconciles against `Root` as
world-restriction.
- The arch guard's SECCOMP_RET_KILL_PROCESS needs kernel 4.14; below it
  the kernel reads an unknown action as kill-thread, weaker than the
  documented kill, and nothing probes for it — a host probe for chunk
  5's row selection.
