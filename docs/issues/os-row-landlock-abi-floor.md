# The OS row's Landlock ABI floor

Lands: user decision

The Linux OS row is reached wherever the kernel exposes Landlock at
any ABI. The exposure a row without namespaces leaves open to
processes of the same user (docs/specs/sandbox.md, "Root is
world-restriction") is closed in part by Landlock's IPC scoping —
abstract unix sockets and signals confined to the domain — which
ABI 6 (kernel 6.12) introduced and the row applies where it is
there; below it, a payload can signal any same-user process, the
caller included, and reach any abstract socket. Unix sockets by
path stay reachable at every ABI.

The fork: require ABI 6 for the row, so every OS-tier run has the
closed exposure and a kernel below it reaches Minimal — which
refuses every `Root` and denied-network intent, so pb runs no
plugin there — at the cost of the ABI 4 and 5 kernels, Ubuntu
24.04's 6.8 GA kernel among them; or admit every ABI, the exposure
stated in the spec and accepted through `MinTier` as the row's
other exposures are, the scoping applied where the kernel has it.
The tradeoff is externally visible: which hosts run an OS-tier
plugin at all, against what an admitted plugin can reach on the
older ones.
