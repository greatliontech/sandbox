# The rows' close-out campaigns

The darwin chunk (the Seatbelt row, landed from 3b0c5f8 to 123ef8f)
and the windows chunk (the AppContainer row, from 123ef8f on) each
closed without a completed `gomutant run` campaign over its
Linux-reachable delta: the darwin chunk's run was aborted by a tree
change under measurement and then killed by the system for memory;
the windows chunk's could not start, the mutation server
unreachable for the session that closed it, and a campaign is
started only when the user asks. Each chunk's invariants have their
witnesses (the darwin row's and the windows row's own tests on CI,
hand probes over the portable resolution killed by `TestBarred`),
but their Linux-reachable deltas have no survivor list.

Resolution: one campaign covers both — `gomutant run --changed
3b0c5f8` on Linux (the darwin and windows files have no Linux
oracle and are outside its reach) — and every survivor is
dispositioned: a vacuous or missing test strengthened, never a
mutation kept.

Lands: `gomutant run --changed 3b0c5f8` completed and its survivors
dispositioned.
