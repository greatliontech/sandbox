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
weaker guarantee than it asked for (`Spec.MinTier`).

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
| linux | create-only namespaces (`SysProcAttr` clone) + uid/gid map + pivoted read-only root with path grants + capability drop + seccomp (a native-ABI policy behind an arch guard) + no_new_privs + rlimits | `Strong` | namespace core, the Root world, and hardening delivered; cgroups pending |
| windows | AppContainer + Job Object (`KILL_ON_JOB_CLOSE`) | `OS` | skeleton |
| darwin | `sandbox-exec` SBPL profile + `setrlimit` | `OS` | skeleton |
| other | — | — | `ErrUnsupported` |

Linux strong-tier off Linux (Hyper-V / Virtualization.framework micro-VM running
the Linux backend) is a future tier, not yet wired.

## Roadmap

1. **Linux**: cgroup v2 limits via `SysProcAttr.UseCgroupFD` (rootfs
   pivot, bind-mounted path grants, capability drop, and seccomp landed).
2. **Windows**: AppContainer profile + Job Object; named-pipe transport plumbing.
3. **macOS**: SBPL generation + `sandbox-exec`; runtime availability probe that
   degrades `Tier()` to `Minimal` when Seatbelt is unavailable.
4. Resource-usage `Stats` per backend.

## Spike

```
go run ./cmd/spike      # runs /bin/sh in fresh PID/UTS/NET/IPC/user namespaces
go test ./...           # asserts the isolation (skips if userns is unavailable)
```
