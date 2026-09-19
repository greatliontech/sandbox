# The code does not yet conform to the contract

Lands: strong-backend plan chunk 5 (row selection and tier derivation close the remaining gaps)

docs/specs/sandbox.md pins the contract ahead of the code. The known
nonconformities, so none is silent:

- `Tier()` asserts `Strong` unconditionally although every arm of
  the Strong row is now delivered — the spec requires tier derived
  from the row that fully applied, which chunk 5's row selection
  makes true.
- The `MinTier` gate compares against a constant maximum, so it can
  never refuse: "fails closed before exec" currently fails open, and
  no host probes exist to select a row.
- `Spec.Root` is delivered on the Strong row (pivoted read-only,
  grants and rendezvous bound, entrypoint from the tree) with
  composition failures refusing `Start`; rows without mount
  namespaces have no `Root` handling yet.
- Bounds ride cgroups where the host affords placement and rlimits
  otherwise, and `Stats` reports the accounting and its counters; the
  live cgroups arms — placement, the vacating of a delegated cgroup
  that holds the caller, the counters — run only under a delegated
  subtree (`SANDBOX_TEST_REQUIRE_CGROUPS` demands them).
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
- Cancellation kills through the cgroup where the run was placed in
  one and through the pid namespace's init otherwise; caller death
  still reaches the direct child alone (`Pdeathsig`), which on this
  row is the namespace's init and so the whole namespace.

Consumer note: pb's REQ-plugin-sandboxed wording assumes the
at-`/` root view the Strong row presents; when an `OS`-tier row first
reaches pb, that spec's wording reconciles against `Root` as
world-restriction.
- The arch guard's SECCOMP_RET_KILL_PROCESS needs kernel 4.14; below it
  the kernel reads an unknown action as kill-thread, weaker than the
  documented kill, and nothing probes for it — a host probe for chunk
  5's row selection.
