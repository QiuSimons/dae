/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */
package control

import (
	"context"
	"net/netip"
	"time"

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
		Ifindex:  0,
	}

	// Special handling: try to get correct Ifindex from BPF with timeout to avoid blocking
	bpfCtx, bpfCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer bpfCancel()
	
	done := make(chan struct{})
	var actualResult *bpfRoutingResult
	
	go func() {
		defer close(done)
		if result, err := c.core.RetrieveRoutingResult(p.Src, p.Dest, unix.IPPROTO_TCP); err == nil {
			actualResult = result
		}
	}()
	
	select {
	case <-done:
		if actualResult != nil {
			routingResult.Ifindex = actualResult.Ifindex
		}
	case <-bpfCtx.Done():
		// BPF query timed out, continue with default Ifindex
	}

	// Handle dial target selection and rerouting
	outboundIndex := consts.OutboundIndex(routingResult.Outbound)
	dialTarget, shouldReroute, _ := c.ChooseDialTarget(outboundIndex, p.Dest, p.Domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	// Handle control plane routing
	switch outboundIndex {
	case consts.OutboundControlPlaneRouting:
		if idx, mark, _, err := c.Route(p.Src, p.Dest, p.Domain, consts.L4ProtoType_TCP, routingResult); err == nil {
			outboundIndex = idx
			routingResult.Mark = mark
			routingResult.Outbound = uint8(outboundIndex)
			dialTarget, _, _ = c.ChooseDialTarget(outboundIndex, p.Dest, p.Domain)
		} else {
			return nil, err
		}
	}

	// Set default mark if not specified
	if routingResult.Mark == 0 {
		routingResult.Mark = c.soMarkFromDae
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
		Dest:          dialTarget,
	}

	// Use the new architecture to get dial option
	dialOption, err := c.RouteDialOption(routeParam)
	if err != nil {
		return nil, err
	}

	// Perform the actual dial using the new architecture
	
	ctx := context.Background()
	conn, err := dialOption.Dialer.DialContext(ctx, common.MagicNetwork("tcp", dialOption.Mark), dialOption.DialTarget)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
