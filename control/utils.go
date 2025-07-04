/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"structs"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type RouteParam struct {
	routingResult *bpfRoutingResult
	networkType   *dialer.NetworkType
	Domain        string
	Src           netip.AddrPort
	Dest          netip.AddrPort
}

type DialOption struct {
	DialTarget    string
	Dialer        *dialer.Dialer
	Outbound      *outbound.DialerGroup
	OutboundIndex consts.OutboundIndex
	isFallback    bool
	Mark          uint32
}

func (c *ControlPlane) RouteDialOption(p *RouteParam) (dialOption *DialOption, err error) {
	// TODO: Why not directly transfer routingResult
	outboundIndex := consts.OutboundIndex(p.routingResult.Outbound)
	mark := p.routingResult.Mark

	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, p.Dest, p.Domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneRouting:
		if outboundIndex, mark, _, err = c.Route(p.Src, p.Dest, p.Domain, p.networkType.L4Proto.ToL4ProtoType(), p.routingResult); err != nil {
			oops.Wrap(err)
			return
		}
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("outbound: %v => <Control Plane Routing>",
				outboundIndex.String(),
			)
		}
		// Reset dialTarget.
		dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, p.Dest, p.Domain)
	default:
	}
	if mark == 0 {
		mark = c.soMarkFromDae
	}
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			err = oops.Errorf("traffic was dropped due to no-load configuration")
			return
		}
		err = oops.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
		return
	}
	outbound := c.outbounds[outboundIndex]
	// TODO: ChooseDialTarget 应该替我们实现这个逻辑?
	if p.networkType.L4Proto == consts.L4ProtoStr_UDP {
		dialIp = false
	}
	dialer, _, err := outbound.SelectFallbackIpVersion(p.networkType, dialIp)
	if err != nil {
		dialer, _, err = c.outbounds[c.noConnectivityOutbound].Select(p.networkType)
		if err != nil {
			panic(fmt.Sprintf("fail to get fallback dialer %v(%v): %v", c.outbounds[c.noConnectivityOutbound], c.noConnectivityOutbound, err))
		}
		return &DialOption{
			DialTarget:    dialTarget,
			Dialer:        dialer,
			Outbound:      outbound,
			OutboundIndex: outboundIndex,
			isFallback:    false,
			Mark:          mark,
		}, nil
	}
	return &DialOption{
		DialTarget:    dialTarget,
		Dialer:        dialer,
		Outbound:      outbound,
		OutboundIndex: outboundIndex,
		isFallback:    false,
		Mark:          mark,
	}, nil
}

func LogDial(src, dst netip.AddrPort, domain string, dialOption *DialOption, networkType *dialer.NetworkType, routingResult *bpfRoutingResult) {
	if log.IsLevelEnabled(log.InfoLevel) {
		if dialOption.isFallback {
			log.WithFields(log.Fields{
				"network":          networkType.String(),
				"originalOutbound": dialOption.Outbound.Name,
				"fallbackDialer":   dialOption.Dialer.Property().Name,
				"sniffed":          domain,
				"ip":               RefineAddrPortToShow(dst),
				"pid":              routingResult.Pid,
				"ifindex":          routingResult.Ifindex,
				"dscp":             routingResult.Dscp,
				"pname":            ProcessName2String(routingResult.Pname[:]),
				"mac":              Mac2String(routingResult.Mac[:]),
			}).Infof("[%v] %v <-(fallback)-> %v", strings.ToUpper(networkType.String()), RefineSourceToShow(src, dst.Addr()), dialOption.DialTarget)
		} else {
			log.WithFields(log.Fields{
				"network":  networkType.StringWithoutDns(),
				"outbound": dialOption.Outbound.Name,
				"policy":   dialOption.Outbound.GetSelectionPolicy(),
				"dialer":   dialOption.Dialer.Property().Name,
				"sniffed":  domain,
				"ip":       RefineAddrPortToShow(dst),
				"pid":      routingResult.Pid,
				"ifindex":  routingResult.Ifindex,
				"dscp":     routingResult.Dscp,
				"pname":    ProcessName2String(routingResult.Pname[:]),
				"mac":      Mac2String(routingResult.Mac[:]),
			}).Infof("[%v] %v <-> %v", strings.ToUpper(networkType.String()), RefineSourceToShow(src, dst.Addr()), dialOption.DialTarget)
		}
	}
}

type WriteCloser interface {
	CloseWrite() error
}

type ConnWithReadTimeout struct {
	netproxy.Conn
}

func (c *ConnWithReadTimeout) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(consts.DefaultReadTimeout))
	return c.Conn.Read(p)
}

func (c *ControlPlane) Route(src, dst netip.AddrPort, domain string, l4proto consts.L4ProtoType, routingResult *bpfRoutingResult) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	var ipVersion consts.IpVersionType
	if dst.Addr().Is4() || dst.Addr().Is4In6() {
		ipVersion = consts.IpVersion_4
	} else {
		ipVersion = consts.IpVersion_6
	}
	bSrc := src.Addr().As16()
	bDst := dst.Addr().As16()
	if outboundIndex, mark, must, err = c.routingMatcher.Match(
		bSrc[:],
		bDst[:],
		src.Port(),
		dst.Port(),
		ipVersion,
		l4proto,
		domain,
		routingResult.Pname,
		routingResult.Ifindex,
		routingResult.Dscp,
		append([]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, routingResult.Mac[:]...),
	); err != nil {
		return 0, 0, false, err
	}

	return outboundIndex, mark, false, nil
}

func (c *controlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples := &bpfTuplesKey{
		Sip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: srcIp6},
		Sport: common.Htons(src.Port()),
		Dip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: dstIp6},
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}

	var routingResult bpfRoutingResult
	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, &routingResult); err != nil {
		return nil, fmt.Errorf("reading map: key [%v, %v, %v]: %w", src.String(), l4proto, dst.String(), err)
	}
	return &routingResult, nil
}

func RetrieveOriginalDest(oob []byte) netip.AddrPort {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			ip := msg.Data[4:8]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(ip)), port)
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			ip := msg.Data[8:24]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(ip)), port)
		}
	}
	return netip.AddrPort{}
}

func checkIpforward(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("1")) {
		return nil
	}
	return fmt.Errorf("ipforward on %v is off: %v; see docs of dae for help", ifname, path)
}

func CheckIpforward(ifname string) error {
	if err := checkIpforward(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	if err := checkIpforward(ifname, consts.IpVersionStr_6); err != nil {
		return err
	}
	return nil
}

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetIpv4forward(val string) error {
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetForwarding(ifname string, val string) {
	_ = setForwarding(ifname, consts.IpVersionStr_4, val)
	_ = setForwarding(ifname, consts.IpVersionStr_6, val)
}

func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
		return nil
	}
	return fmt.Errorf("send_directs on %v is on: %v; see docs of dae for help", ifname, path)
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetSendRedirects(ifname string, val string) {
	_ = setSendRedirects(ifname, consts.IpVersionStr_4, val)
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname[:], string([]byte{0})))
}

func Mac2String(mac []uint8) string {
	ori := []byte(hex.EncodeToString(mac))
	// Insert ":".
	b := make([]byte, len(ori)/2*3-1)
	for i, j := 0, 0; i < len(ori); i, j = i+2, j+3 {
		copy(b[j:j+2], ori[i:i+2])
		if j+2 < len(b) {
			b[j+2] = ':'
		}
	}
	return string(b)
}
