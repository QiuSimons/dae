package control

import "github.com/daeuniverse/dae/component/outbound"

func (c *ControlPlane) Outbounds() []*outbound.DialerGroup {
	outbounds := make([]*outbound.DialerGroup, len(c.outbounds))
	copy(outbounds, c.outbounds)
	return outbounds
}

func (c *ControlPlane) OutboundByName(name string) *outbound.DialerGroup {
	for _, group := range c.outbounds {
		if group != nil && group.Name == name {
			return group
		}
	}
	return nil
}
