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
  `MinTier` gates it. The selection is a fact a caller may read
  before `Start` (`Reach`): the row this host reaches for a spec, by
  the same probes and the same rule, with what the host lacks for
  the rows above it — so an intent only some rows deliver (a
  hostname, which needs a UTS namespace) is stated against the row
  that will run rather than refused by it. The answer is the
  selection alone, `MinTier` not consulted — a row below the floor
  is `Start`'s refusal — and the tier a run reports is still derived
  from what applied. Reading the selection is the probe: the first
  read in a process runs the probe, the re-exec included, so the
  Re-exec clause governs the read as it governs `Start`.
- **Tier is derived, never asserted.** A backend reports the tier of
  the row whose mechanism set fully applied. There is no other path to
  a tier value.
- **`MinTier` fails closed before exec.** The selected row's tier is
  known before anything runs; a host whose best row sits below
  `MinTier` refuses with `ErrWeakerThanRequired` without running
  anything, the refusal carrying as a value the row reached, the tier
  required, and what the host lacks for the higher rows the backend
  implements — a caller deciding what to say about the refusal reads
  the row, never the message. A `MinTier` naming no tier is refused
  at construction.
- **`Root` is world-restriction.** A stated `Root` bounds the process's
  world: it may read exactly that tree, the granted paths, and the
  platform's execution substrate — what every process on that
  platform necessarily reaches to run, as the platform's own
  baseline for a sandboxed process defines it: nothing on Linux; on
  darwin what Apple's `system.sb` admits — dyld and the shared
  cache, reads under `/System`, `/usr/lib`, `/usr/share` and
  `/Library/Apple`, the timezone database, the passwd and services
  files, the basic devices, the kernel's sysctl facts, the system
  logger's socket, a fixed set of mach services — together, on
  darwin alone, with the sandbox's own calling binary, whose second
  stage runs under the profile before the payload, so the payload
  may read and execute that binary; it writes only where a
  `PathGrant` grants `ReadWrite` and in the rendezvous directory; and
  the entrypoint comes from the tree. Rows with mount namespaces additionally present the
  tree at `/`. Rows without cannot: an entrypoint whose *loading*
  requires the image-absolute layout — dynamic linking against the
  image's own libraries — is refused there rather than run against a
  wrong world, and a payload that dereferences image-absolute paths *at
  runtime* observes different resolution than under an at-`/` row. That
  exposure is what a caller accepts by admitting such rows through
  `MinTier`, together with the IPC a row without namespaces leaves
  open to processes of the same user: unix sockets reached by path
  always; abstract unix sockets and signals where the kernel does
  not scope them to the domain (Landlock ABI 6 does, and the row
  applies the scoping where it is there). A row with no
  filesystem-restriction mechanism at all (`Minimal`) cannot bound
  the world to anything and refuses a stated `Root`
  (`ErrUndeliverable`): the tier grades exposure, and an intent
  nothing delivers is a refusal, never an omission. Grants and the
  rendezvous directory land on entries the caller placed in the tree
  at their own paths — an
  absent or wrong-kind target, or one reached through a symlink at
  any component, is an undeliverable intent, never an omission; so is
  a grant overlapping another grant or the rendezvous directory, two
  intents over one entry having no single delivery, a rendezvous
  directory that is no directory, and a file grant with more than
  one name on the host, which could be the tree's own file under
  another (a hard link, which no path can see) — a read-write
  directory grant holding such a link is the caller's own doing, the
  tree being the caller's to shape — and a read-only grant is
  read-only throughout, submounts included. Containment and overlap
  are judged by the entries named, never by their spellings: every
  spelling the kernel resolves to one entry (a bind mount's, a
  firmlink's, a case variant's, a symlink's) names that entry; a
  grant names, besides its own entry, every mount beneath it, which
  a rule over the grant reaches; and an entry reached through a
  mount grafting a directory of one filesystem onto another path (a
  bind mount of a directory, a firmlink) is reached under its
  origin's spelling too, so a grant above the origin holds it. A
  directory granted twice under two spellings is two intents over
  one entry, which an allowlist would unite on the one inode, and
  the judgement covers the entry a grant lands on in the tree as
  well as its host entry. A spelling the caller cannot read because
  a directory it owns bars it — one the payload, running as the
  caller, could open — leaves what it names unjudged, which is a
  refusal; one barred by another user's directory stays barred to
  the payload and names nothing to the judgement. What presents one
  entry under identities
  of its own — a network or user-space filesystem re-exporting the
  host's own files — is another entry to the judgement, an
  exposure the caller's grants carry; an automount point not yet
  triggered, as a grant or beneath one, presents what its map says
  once a lookup fires it, which the resolution does not do, so what
  it names is unjudged, a refusal like the spelling the caller
  cannot read (an indirect map's point, whose keys mount beneath it,
  is never triggered as a whole); a filesystem presenting
  another's files under their own identity (an overlay's, before a
  copy-up) is that entry, a refusal never an admission. The tree itself
  is never written, not even transiently: a shared, read-only tree is
  a valid `Root`. The environment is caller-supplied state: under a
  `Root` an unstated environment is empty, never the host's.
- **Re-exec is part of the mechanism.** A pure-Go backend creating
  namespaces at clone time runs the calling binary as the sandbox's
  init: it re-execs itself with an internal marker and takes over
  inside the fresh namespaces. Every package init of the calling
  binary runs in that child before the takeover; a consumer's init
  must be free of side effects that the marker environment would make
  wrong — the init child's environment is the internal markers
  alone, nothing of the host's, the payload's environment riding the
  config — and an init child that dies before exec is reported by
  `Start` as such — never as the payload's own exit.
- **Bounded means bounded.** `Limits` map to the strongest accounting
  the selected row admits on its platform (cgroups where a delegated
  subtree accepts both placement and the controllers the limits
  need — a subtree can accept a child yet refuse controller
  delegation, and a cgroup that cannot enforce the stated limits is
  no accounting at all; rlimits; Job Objects). A memory bound is the
  whole of what the process may hold: under cgroups swap is closed to
  the run, never a second allowance past the bound — and a kernel
  that accounts no swap yet can hold it cannot close it, so such a
  host accounts the memory bound by rlimits instead. Where the
  platform affords an unprivileged process no native bound at all —
  darwin, whose kernel refuses every memory rlimit (`RLIMIT_AS`,
  `RLIMIT_DATA`, `RLIMIT_RSS`) and keeps its per-task memory limit
  for root, which delivers the CPU limit as `SIGXCPU`, a signal a
  payload may handle, and whose process limit counts every process
  of the user — the row bounds by a watchdog: the kernel's own
  per-process readings (the physical footprint — the platform's own
  measure of what a process costs, anonymous and compressed pages
  included, file-backed pages not, what its memory-pressure limiter
  reads — the CPU time, the thread count), sampled over the run's
  process group at the stated interval (`WatchdogInterval`), the
  group killed at the bound — the memory bound over the group's
  footprints summed, the CPU bound over each process's own time as
  `RLIMIT_CPU` reads it, the process bound over the threads of the
  group's processes (every process has at least one); a member the
  kernel will not show the sandbox — one that gained privilege — is
  a bound the watchdog cannot hold, which ends the run. Such a bound
  is exceeded by at most what the group can take in one interval,
  and it reaches what the group holds: a process that leaves the
  group (`setsid`) leaves the bounds, the same escape that leaves
  the kill tie, stated under "No orphans"; the accounting reported
  names the watchdog, and its one kill is counted by the bound that
  made it (memory, CPU or process). Where the kernel holds a bound
  the sign is the kernel's own, read for the caller: a memory
  cgroup's kills and a pid cgroup's refused forks from the cgroup's
  own counters, `RLIMIT_CPU`'s kill — its soft and hard limits one,
  so the kernel ends the process at the limit rather than
  signalling it — from the dead process's own CPU time at the bound
  as the kernel accounts it, within the allowance the kernel's tick
  and the reading's truncation leave; a memory or process rlimit refuses the payload alone,
  an allocation or a fork, and kills nothing. Which accounting
  enforced the bounds is a reported fact of the run, so a
  bound-exceeded death is attributable on every row delivered.
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
  consent. On darwin the run's end is a third trigger: when the
  payload exits — before it is reaped, so a descendant holding its
  pipes cannot hold the caller's Wait open — the group's remnants
  are killed, there being no namespace to take a descendant with
  it.

## Mechanism ladder

| Platform + host condition | Mechanism set (applied whole) | Tier |
|---|---|---|
| linux, unprivileged user namespaces available | namespaces (user, mount, pid, uts, ipc; net unless granted), pivoted read-only root repeating locked mount flags, capability drop, seccomp holding for every syscall ABI the kernel exposes (a foreign-ABI call is killed, never let through unfiltered), `no_new_privs`, cgroup-or-rlimit bounds | `Strong` |
| linux, user namespaces unavailable, Landlock available | Landlock filesystem allowlist over the world at its host paths (the caller's whole world where no `Root` is stated), seccomp network denial at the socket (Landlock ABI 4's TCP restrictions are supplementary, never the sole arm — UDP and raw sockets stay open without seccomp; an ABI that also multiplexes the socket calls through `socketcall` refuses that route whole, the local family reached by the direct calls), Landlock's IPC scoping where the kernel has it (ABI 6), `no_new_privs`, cgroup-or-rlimit bounds; static entrypoints only under a `Root` — an ELF the kernel loads whole, native, with no interpreter; a script, a dynamically linked executable, or a file the check cannot read is refused | `OS` |
| darwin, Seatbelt available (`sandbox-exec` applies a profile) | Seatbelt profile: under a `Root`, nothing by default but the platform's execution substrate as Apple's own `system.sb` states it (dyld, the system libraries and frameworks, the services every process reaches, name resolution not among them) less the one place it lets a process create files (`/cores`), the tree read, mapped and executed at its host path so an entrypoint may load the tree's own libraries and execute a sibling of the tree, the calling binary read and executed (its second stage runs under the profile before the payload: an exposure of that binary's bytes and its execution to the payload), grants read, mapped and executed as on the Linux `OS` row and read-write ones written, the rendezvous directory read and written with unix sockets within it alone, the network by address where granted, the platform's name resolution with it (a unix socket elsewhere on the host is not the network); the entrypoint an executable Mach-O image for the machine — the machine being the one the calling binary runs for; an image for another machine the host could translate is refused all the same — whose dynamic linker, libraries and run paths are the substrate's or relative to the image and which sets no loader environment, a script or an image linked at an image-absolute path refused; a grant's two spellings of one directory (a firmlink's, a case variant's) judged one, by identity as everywhere; without a `Root`, the whole world with the network denied at the socket — the platform's mach services stay reachable, name resolution among them, as a row without namespaces leaves IPC — and a read-only grant refused, the profile over the whole world having no rule a renamed ancestor cannot carry a grant out of; the profile matching the kernel's own spelling of every path; rlimit bounds with the watchdog behind them | `OS` |
| windows, AppContainer available | AppContainer boundary, Job Object bounds | `OS` |
| any platform where no security boundary is available but resource bounds are | resource bounds (rlimits, Job Object, darwin's watchdog) | `Minimal` |
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
guarantees exactly this much: bounds exist by the strongest
accounting the platform affords, kernel-enforced where it has one,
and their accounting is reported — it grades nothing else, so it refuses every
intent only a security boundary delivers (`Root`, `Hostname`, a denied
network, a read-only grant), and a `Spec` stating no `Limits` leaves
it nothing to apply and is refused too (`ErrUndeliverable`). A host
reaching only `Minimal` runs only if `MinTier` admits it; a platform
matching no row refuses with `ErrUnsupported` rather than running
unsandboxed — on Linux and darwin `Minimal` is always satisfied,
rlimits existing on every kernel and the watchdog on every darwin,
so neither host ever refuses that way.
Tier `None` stays in the vocabulary as the floor `MinTier` can state
— "accept anything" — but no row reports it: sandbox never bare-execs.
