package outbound

import "github.com/daeuniverse/dae/component/outbound/dialer"

func (g *DialerGroup) FindDialerByName(name string) (int, *dialer.Dialer) {
	for i, d := range g.Dialers {
		if d == nil || d.Property() == nil {
			continue
		}
		if d.Property().Name == name {
			return i, d
		}
	}
	return -1, nil
}

func (g *DialerGroup) CurrentFixedDialer() *dialer.Dialer {
	state := g.currentSelectionState()
	if state.policy.Policy != "fixed" {
		return nil
	}
	if state.policy.FixedIndex < 0 || state.policy.FixedIndex >= len(g.Dialers) {
		return nil
	}
	return g.Dialers[state.policy.FixedIndex]
}
