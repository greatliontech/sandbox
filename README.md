# sandbox

A pure-Go, cross-platform library that launches **one process in an OS-enforced
sandbox**. Built for [pb](https://github.com/greatliontech/pb) and
[ociplug](https://github.com/greatliontech/ociplug). The full contract —
identity, tier derivation, and the per-platform mechanism ladder — is
[docs/specs/sandbox.md](docs/specs/sandbox.md).

It is deliberately **create-only**: it always creates a fresh isolated
environment and execs one process into it — it never joins a running one. That
single restriction is what keeps it **100% pure Go** everywhere: the
single-threaded `setns` constraint that forces cgo in full container runtimes
(`runc`, and our own [`container`](https://github.com/greatliontech/container))
applies only to *joining* namespaces, never to *creating* them at clone time
(container additionally routes its create path through C by choice in cgo
builds).

> For the full container-runtime ambition (image lifecycle, `exec`-into-running,
> OCI compliance) see `greatliontech/container`. `sandbox` is a narrower, simpler
> thing on purpose.

## Contract

One interface; each platform provides the strongest mechanism it can and
**reports the tier it actually achieved**, so a caller never gets a silently
weaker guarantee than it asked for (`Spec.MinTier`). The row a host
reaches for a spec can be read before a run (`Reach`), so an intent
only some rows deliver — a hostname — is stated against the row
that will run.

| Tier | Meaning |
|---|---|
| `Strong` | kernel-enforced (Linux namespaces) |
| `OS` | OS-policy boundary (Landlock, Seatbelt, AppContainer) |
| `Minimal` | kernel-enforced resource bounds, accounting reported; no security boundary |
| `None` | floor only — `MinTier: None` accepts any row; no backend reports it |

```go
sb, _ := sandbox.New(sandbox.Spec{
    Exec:     "/bin/sh",
    Args:     []string{"-c", "echo pid=$$"},
    Hostname: "plugin",
})
sb.Start(context.Background())
es, _ := sb.Wait()
fmt.Println(es.Code, sb.Tier())
```

## Backends

| GOOS | Mechanism | Target tier | Status |
|---|---|---|---|
| linux | create-only namespaces (`SysProcAttr` clone) + uid/gid map + pivoted read-only root with path grants + capability drop + seccomp (a native-ABI policy behind an arch guard) + no_new_privs + cgroup-or-rlimit bounds with reported accounting | `Strong` | delivered; a host without user namespaces reaches the `OS` row where it has Landlock — the world allowlisted at its host paths, the network denied at the socket, static entrypoints only — and the `Minimal` row otherwise: bounds only, refusing every intent needing a boundary (`Root`, `Hostname`, a denied network, read-only grants) and a spec with no limits, `MinTier` gating both |
| windows | an AppContainer of the run's own (the tree under a `Root`, or the entrypoint's directory without one, the grants and the rendezvous directory granted to its identity at their host paths for the run; the network withheld unless granted) + a Job Object every process of the run is born into, holding the bounds (memory killed on the Job's report, the CPU by a watchdog over the Job's account, the process count refused) and the kill tie (`KILL_ON_JOB_CLOSE`) | `OS` | delivered; a host without an AppContainer reaches `Minimal` (the Job alone) |
| darwin | `sandbox-exec` SBPL profile (deny by default over Apple's `system.sb` substrate under a `Root`, the tree and grants allowlisted at the kernel's spelling; the whole world with the network denied without one) + rlimits with a watchdog over the kernel's per-process readings for the bounds the kernel will not hold (memory, CPU past `SIGXCPU`, the thread count) | `OS` | delivered; a host without `sandbox-exec` reaches the `Minimal` row |
| other | — | — | `ErrUnsupported` |

Linux strong-tier off Linux (Hyper-V / Virtualization.framework micro-VM running
the Linux backend) is a future tier, not yet wired.

## Roadmap

1. Resource-usage `Stats` per backend.

## Spike

```
go run ./cmd/spike      # runs /bin/sh in fresh PID/UTS/NET/IPC/user namespaces
go test ./...           # asserts the isolation; the Strong row's arms skip where user
                        # namespaces are unavailable, the OS row's where Landlock is not,
                        # the cgroup arms where placement is: SANDBOX_TEST_REQUIRE_USERNS=1,
                        # SANDBOX_TEST_REQUIRE_LANDLOCK=1 and SANDBOX_TEST_REQUIRE_CGROUPS=1
                        # make each a failure instead, as continuous integration runs
                        # them under systemd-run --user --scope -p Delegate=yes
```
