# Plan: the rows below Strong

Spec: docs/specs/sandbox.md (the ladder: the Linux OS row, the
darwin row)

- [x] 1. The Linux OS row: Landlock filesystem allowlist, seccomp
      network denial, no_new_privs, rlimit bounds, static entrypoints
      only, reached by a host without unprivileged user namespaces
- [x] 2. The darwin row: a Seatbelt profile delivering the OS tier,
      so a Start on darwin succeeds and reports a tier
  - [x] 2.1. Triage gate.
  - [x] 2.2. The rows, the probe and the bounds: `sandbox-exec`
        probed for the `OS` row, the `Minimal` row beneath it;
        `Reach` by the same selection; the init trampoline (the
        calling binary re-executed, the config and status pipes, the
        process group) shared with Linux where it is the same;
        bounds by the kernel's rlimits where it enforces them (CPU,
        open files) and by a watchdog over the kernel's
        per-process readings where it has no native bound (memory,
        and CPU behind the signal a payload may handle), reported as
        its own accounting with its interval; the spec amended so;
        the macOS CI row demanding the `OS` row.
  - [x] 2.3. The Seatbelt row's world: the profile (deny by default,
        Apple's `system.sb` as the execution substrate, the tree read
        and executed, grants and the rendezvous directory at their
        host paths, the network denied or granted whole, unix
        sockets within the rendezvous directory), the world resolved
        as the Linux `OS` row resolves it (shared), the entrypoint's
        load commands held to the substrate and the tree, a sibling
        of the tree executed by the entrypoint admitted; the world
        probe payload run under it on the macOS row.
  - [x] 2.4. Close-out: consolidation (the world resolution and the
        trampoline shared across the platforms' rows), the spec's
        darwin statements settled, the campaign.
- [ ] 3. The windows row: an AppContainer boundary and Job Object
      bounds delivering the OS tier, so a Start on windows succeeds
      and reports a tier
  - [ ] 3.1. Triage gate.
  - [ ] 3.2. The rows, the probe and the bounds: the AppContainer
        probed for the `OS` row, the `Minimal` row beneath it (a Job
        Object alone); `Reach` by the same selection; the Job
        Object's bounds (memory, CPU time, the process count) with
        its kill-on-close as the kill tie; the accounting reported;
        the windows CI row demanding the `OS` row.
  - [ ] 3.3. The AppContainer row's world: the tree, the grants and
        the rendezvous directory granted to the container's
        capability at their host paths, the network denied or
        granted whole, the entrypoint held to what the row can load,
        a sibling of the tree executed by the entrypoint admitted;
        the world probe payload run under it on the windows row.
  - [ ] 3.4. Close-out: consolidation, the spec's windows statements
        settled, the campaign.
