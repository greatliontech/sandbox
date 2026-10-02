# One world-resolution driver for the rows presenting the tree at its host path

The darwin and windows rows resolve a spec to their world by the
same sequence: the spelling check, the row's refusals, the shared
tree resolution, then a mapping of its binds onto the row's
mechanism (the kernel's spelling of each path on darwin; the
container's grantees at their canonical host paths on windows). The
sequence is spelled twice (`resolveWorld` in sandbox_darwin.go and
in sandbox_windows.go), with the Linux rows' own resolution beside
it.

Collapse: one portable driver taking the row's refusals and a
per-platform mapping of the tree world, each platform file keeping
the mapping alone; the Linux resolution folded in where its shape
is the same, kept apart where the pivot differs. Invariants
preserved: the order (spelling, refusals, resolution) and every
refusal of the shared resolution.

Lands: docs/plans/rows.md chunk 3.4 (the windows row's close-out
consolidation).
