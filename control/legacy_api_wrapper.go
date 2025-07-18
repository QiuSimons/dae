/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

// RouteDialParam maintains the exact same structure as the old API
type RouteDialParam struct {
	Outbound    consts.OutboundIndex
	Domain      string
	Mac         [6]uint8
	Dscp        uint8
	ProcessName [16]uint8
	Src         netip.AddrPort
	Dest        netip.AddrPort
	Mark        uint32
}

// RouteDialTcp provides backward compatibility with the old API
// It wraps the new architecture (RouteDialOption + DialContext) to maintain the same interface
func (c *ControlPlane) RouteDialTcp(p *RouteDialParam) (conn netproxy.Conn, err error) {
	// Create bpfRoutingResult from the old RouteDialParam (same as old API)
	routingResult := &bpfRoutingResult{
		Mark:     p.Mark,
		Must:     0,
		Mac:      p.Mac,
		Outbound: uint8(p.Outbound),
		Pname:    p.ProcessName,
		Pid:      0,
		Dscp:     p.Dscp,
		Ifindex:  0, // Default to 0
	}

	// Special handling: try to get correct Ifindex from BPF
	if actualResult, err := c.core.RetrieveRoutingResult(p.Src, p.Dest, unix.IPPROTO_TCP); err == nil {
		routingResult.Ifindex = actualResult.Ifindex
	}

	// Create NetworkType from destination info
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionFromAddr(p.Dest.Addr()),
		IsDns:     false,
	}

	// Create new RouteParam from old RouteDialParam
	routeParam := &RouteParam{
		routingResult: routingResult,
		networkType:   networkType,
		Domain:        p.Domain,
		Src:           p.Src,
		Dest:          p.Dest,
	}

	// Use the new architecture to get dial option
	dialOption, err := c.RouteDialOption(routeParam)
	if err != nil {
		return nil, err
	}

	// Perform the actual dial using the new architecture
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()

	conn, err = dialOption.Dialer.DialContext(ctx, common.MagicNetwork("tcp", dialOption.Mark), dialOption.DialTarget)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
