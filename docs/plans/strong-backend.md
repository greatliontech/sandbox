# Strong backend

Deliver docs/specs/sandbox.md's Linux Strong row whole: the mechanism
layer seeded from container@866eb725dc6be9acb1ac36fd66ce8152280e71aa,
the Strong world and hardening, bounds with reported accounting, and
row selection with derived tiers.

- [x] 1. Mechanism verbs (`internal/nslinux`): mount verbs (bind,
      pivot, read-only remount repeating locked flags), hardening
      verbs (capability drop, seccomp, no_new_privs, rlimits), cgroup
      verbs (availability, delegated-subtree discovery, create with
      clone-into fd, resource writes, kill), each fail-loud with its
      kernel preconditions documented; unit tests for every verb
      testable without namespaces.
- [ ] 2. The Strong world: `Spec.Root` pivoted with the read-only
      remount, `PathGrants` and the rendezvous directory as binds,
      entrypoint from the tree; live namespace tests (write probe,
      world-view probe) with a skip guard for restricted hosts.
- [ ] 3. Strong hardening: capability drop, seccomp, no_new_privs,
      network-namespace denial with the `Network` grant; live probes
      (dial, capability read).
- [ ] 4. Bounds: cgroup placement via the delegated subtree and
      clone-into with the rlimit fallback, the accounting reported on
      the public surface, `cgroup.kill` wired into cancellation
      cleanup; live memory-bound test.
- [ ] 5. Row selection and honest reporting: host probes, the
      highest-satisfied-row rule, tier derived from the applied row,
      `MinTier` failing closed before exec, `ErrUndeliverable`
      distinct from `ErrWeakerThanRequired`; conformance close-out.
