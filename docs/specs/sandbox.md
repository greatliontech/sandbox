# sandbox

The policy-level contract for running one untrusted process behind the
strongest boundary the platform and host afford.

## Identity

A caller states intent — what the process may see (a root filesystem,
path grants, a hostname, a rendezvous directory, network), what it may
consume (limits), and the weakest boundary it will accept (`MinTier`) —
never mechanism. sandbox selects the strongest mechanism available on
this platform *and this host*, applies it whole, and reports the
isolation tier actually achieved.

Mechanism never enters a request: no mount lists, no device nodes, no
caller-supplied seccomp programs, no consoles, and no joining of
existing sandboxes. A run's *report* may name mechanism facts — the
achieved tier, the accounting that enforced the bounds — because
stating what happened offers no knob. The moment `Spec` grows a
mechanism input, this identity has dissolved into a container
runtime's — that runtime exists (`greatliontech/container`) and is
deliberately a different thing: mechanism-level, Linux-only, knobs
exposed, faithful to the container model. The two projects are
independent by design.

## Contract

- **Create-only.** sandbox always creates a fresh isolated environment
  and execs one process into it; it never joins a running one. This is
  what keeps every backend pure Go: the single-threaded `setns`
  constraint that forces cgo applies only to joining, never to creating
  at clone time.
- **Intent is portable; delivery is all-or-nothing.** One `Spec` means
  the same intent on every platform. A backend that cannot deliver a
  stated intent refuses `Start`; it never approximates silently. The
  tier grades how strongly delivered intent is enforced — it never
  substitutes for delivery. A `PathGrant` is a bind mount under one
  mechanism and an allowlist rule under another, and the caller cannot
  tell; a stated `Hostname` on a row with no way to present one is a
  refusal, not an omission. An undeliverable intent is its own refusal
  (`ErrUndeliverable`), distinguishable from a tier refusal
  (`ErrWeakerThanRequired`): "this host cannot do what you asked" and
  "this host cannot do it strongly enough" call for different caller
  responses.
- **Rows are selected by probes, then applied whole.** Before exec, the
  backend selects the highest ladder row this host's probed facts
  satisfy — user-namespace availability, Landlock ABI, profile
  support. The selected row's mechanism set then applies
  all-or-nothing: an application failure fails `Start`, it never
  quietly re-selects a lower row. Downgrade exists only at selection
  time and is visible — the reported tier names the row that ran, and
  `MinTier` gates it.
- **Tier is derived, never asserted.** A backend reports the tier of
  the row whose mechanism set fully applied. There is no other path to
  a tier value.
- **`MinTier` fails closed before exec.** The selected row's tier is
  known before anything runs; a host whose best row sits below
  `MinTier` refuses with `ErrWeakerThanRequired` without running
  anything.
- **`Root` is world-restriction.** A stated `Root` bounds the process's
  world: it may read exactly that tree, the granted paths, and the
  platform's execution substrate (the runtime every process on that
  platform necessarily maps: dyld and the system libraries on darwin,
  nothing on Linux); it writes only where a `PathGrant` grants
  `ReadWrite` and in the rendezvous directory; and the entrypoint comes
  from the tree. Rows with mount namespaces additionally present the
  tree at `/`. Rows without cannot: an entrypoint whose *loading*
  requires the image-absolute layout — dynamic linking against the
  image's own libraries — is refused there rather than run against a
  wrong world, and a payload that dereferences image-absolute paths *at
  runtime* observes different resolution than under an at-`/` row. That
  exposure is exactly what a caller accepts by admitting such rows
  through `MinTier`. Grants and the rendezvous directory land on
  entries the caller placed in the tree at their own paths — an
  absent or wrong-kind target, or one reached through a symlink at
  any component, is an undeliverable intent, never an omission; so is
  a grant overlapping another grant or the rendezvous directory, two
  intents over one path having no single delivery — and a read-only
  grant is read-only throughout, submounts included. The tree itself
  is never written, not even transiently: a shared, read-only tree is
  a valid `Root`. The environment is caller-supplied state: under a
  `Root` an unstated environment is empty, never the host's.
- **Re-exec is part of the mechanism.** A pure-Go backend creating
  namespaces at clone time runs the calling binary as the sandbox's
  init: it re-execs itself with an internal marker and takes over
  inside the fresh namespaces. Every package init of the calling
  binary runs in that child before the takeover; a consumer's init
  must be free of side effects that the marker environment would make
  wrong, and an init child that dies before exec is reported by
  `Start` as such — never as the payload's own exit.
- **Bounded means bounded.** `Limits` map to the strongest native
  accounting the selected row admits (cgroups where a delegated
  subtree accepts both placement and the controllers the limits
  need — a subtree can accept a child yet refuse controller
  delegation, and a cgroup that cannot enforce the stated limits is
  no accounting at all; rlimits; Job Objects). Which accounting enforced
  the bounds is a reported fact of the run, so a bound-exceeded death
  is attributable.
- **The wall clock belongs to the caller.** `Start`'s context governs
  the process lifetime; sandbox adds no timeout of its own.
- **No orphans, to the strongest tie the host affords.** Two triggers,
  two strengths. On *context cancellation* the caller's code runs and
  issues the strongest kill the host holds: the PID namespace or Job
  Object where the row has one; the cgroup's kill — by whichever of
  `cgroup.kill` or freeze-then-drain the kernel affords, the freeze
  making the drain impossible to outrun by forking — where the run was
  placed in a delegated subtree (a cgroup is accounting, not a
  security boundary, so any row can hold one); each of those
  unescapable; and the process group otherwise, which a payload can
  leave with `setsid`. On *caller death* nothing of the caller runs
  and only a kernel-side lifetime tie fires: a Job Object's
  kill-on-close, or Linux's parent-death signal — which reaches the
  direct child alone, so on Linux rows without a PID namespace a
  forked descendant can outlive the caller, and darwin has no
  parent-death tie at all — the sandboxed process itself survives a
  caller `SIGKILL` there. Both strengths are stated, never silent;
  admitting rows with the weaker ties through `MinTier` is informed
  consent.

## Mechanism ladder

| Platform + host condition | Mechanism set (applied whole) | Tier |
|---|---|---|
| linux, unprivileged user namespaces available | namespaces (user, mount, pid, uts, ipc; net unless granted), pivoted read-only root repeating locked mount flags, capability drop, seccomp holding for every syscall ABI the kernel exposes (a foreign-ABI call is killed, never let through unfiltered), `no_new_privs`, cgroup-or-rlimit bounds | `Strong` |
| linux, user namespaces unavailable, Landlock available | Landlock filesystem allowlist, seccomp network denial (Landlock ABI 4's TCP restrictions are supplementary, never the sole arm — UDP and raw sockets stay open without seccomp), `no_new_privs`, rlimit bounds; static entrypoints only | `OS` |
| darwin, Seatbelt available | Seatbelt profile (filesystem allowlist, network denial), rlimit bounds | `OS` |
| windows, AppContainer available | AppContainer boundary, Job Object bounds | `OS` |
| any platform where no security boundary is available but resource bounds are | resource bounds (rlimits, Job Object) | `Minimal` |
| anything else | refused (`ErrUnsupported`) | — |

The ladder is normative: a backend selects the highest row its host's
probed facts satisfy, delivers that row's mechanism set whole, and
reports that row's tier — never a blend of rows. One named exception
to whole-row delivery: a row's bounds *accounting* is host-selected —
on Linux a delegated cgroup subtree where placement and controller
delegation are available and rlimits otherwise, a Job Object on
windows — because the security
boundary is what the tier grades; the accounting that enforced the
bounds is a reported fact of the run, so coarser bounds are
attributable, never silent. A `Minimal` selection accordingly
guarantees exactly this much: kernel-enforced bounds exist and their
accounting is reported — it grades nothing else. A host reaching only
`Minimal` runs only if `MinTier` admits it; a platform matching no row
refuses with `ErrUnsupported` rather than running unsandboxed. Tier
`None` stays in the vocabulary as the floor `MinTier` can state —
"accept anything" — but no row reports it: sandbox never bare-execs.
