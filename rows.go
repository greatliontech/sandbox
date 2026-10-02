//go:build linux || darwin || windows

package sandbox

import "fmt"

// minimalRefuses names the intent the Minimal row cannot deliver on
// any platform: its mechanism set is bounds alone, so it refuses
// every intent only a security boundary delivers — a Root, a
// hostname, a denied network, a read-only grant — and a Spec stating
// no limits, which would leave the row nothing to apply (sandbox
// never bare-execs). undeliverable spells the row's refusal.
func minimalRefuses(spec Spec, undeliverable func(what string) error) error {
	switch {
	case spec.Root != "":
		return undeliverable("cannot restrict the world to a Root")
	case spec.Hostname != "":
		return undeliverable("presents no hostname")
	case !spec.Network:
		return undeliverable("cannot deny the network: Network must be granted to run on it")
	}
	for _, g := range spec.PathGrants {
		if g.Access == ReadOnly {
			return undeliverable(fmt.Sprintf("cannot make grant %s read-only", g.Path))
		}
	}
	if spec.Limits == (Limits{}) {
		return undeliverable("applies bounds only, and none were stated: sandbox never bare-execs")
	}
	return nil
}
