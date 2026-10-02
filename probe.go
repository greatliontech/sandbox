package sandbox

import (
	"context"
	"sync"
)

// probeCache holds once-per-process answers to host probes, keyed
// by what was probed. A probe's outcome is a fact for the process's
// lifetime — an anomaly included: a consumer init that breaches the
// re-exec contract breaches it every time — but a probe the caller's
// context ended is not an answer and is not remembered. Callers
// racing for the first answer wait on the lock, bounded by the
// prober's own deadline. A host that changes underneath a running
// caller is not modelled.
type probeCache[T any] struct {
	mu      sync.Mutex
	results map[string]probeResult[T]
}

type probeResult[T any] struct {
	value T
	err   error
}

func (c *probeCache[T]) get(ctx context.Context, key string, probe func(context.Context) (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.results == nil {
		c.results = map[string]probeResult[T]{}
	}
	if r, ok := c.results[key]; ok {
		return r.value, r.err
	}
	v, err := probe(ctx)
	if ctx.Err() != nil {
		var zero T
		return zero, ctx.Err()
	}
	c.results[key] = probeResult[T]{value: v, err: err}
	return v, err
}
