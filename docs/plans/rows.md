# Plan: the rows below Strong

Spec: docs/specs/sandbox.md (the ladder: the Linux OS row, the
darwin row)

- [x] 1. The Linux OS row: Landlock filesystem allowlist, seccomp
      network denial, no_new_privs, rlimit bounds, static entrypoints
      only, reached by a host without unprivileged user namespaces
- [ ] 2. The darwin row: a Seatbelt profile delivering the OS tier,
      so a Start on darwin succeeds and reports a tier
  - [ ] 2.1. Triage gate.
  - [ ] 2.2. The rows, the probe and the bounds: `sandbox-exec`
        probed for the `OS` row, the `Minimal` row beneath it;
        `Reach` by the same selection; the init trampoline (the
        calling binary re-executed, the config and status pipes, the
        process group) shared with Linux where it is the same;
        bounds by the kernel's rlimits where it enforces them (CPU,
        open files, processes) and by a watchdog over the kernel's
        per-process readings where it has no native bound (memory,
        and CPU behind the signal a payload may handle), reported as
        its own accounting with its interval; the spec amended so;
        the macOS CI row demanding the `OS` row.
  - [ ] 2.3. The Seatbelt row's world: the profile (deny by default,
        Apple's `system.sb` as the execution substrate, the tree read
        and executed, grants and the rendezvous directory at their
        host paths, the network denied or granted whole, unix
        sockets within the rendezvous directory), the world resolved
        as the Linux `OS` row resolves it (shared), the entrypoint's
        load commands held to the substrate and the tree, a sibling
        of the tree executed by the entrypoint admitted; the world
        probe payload run under it on the macOS row.
  - [ ] 2.4. Close-out: consolidation (the world resolution and the
        trampoline shared across the platforms' rows), the spec's
        darwin statements settled, the campaign.
