/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
)

var (
	systemDnsMu              sync.Mutex
	systemDns                netip.AddrPort
	systemDnsNextUpdateAfter time.Time

	ErrBadDnsAns = fmt.Errorf("bad dns answer")

	FallbackDns netip.AddrPort
)

func TryUpdateSystemDns() (err error) {
	systemDnsMu.Lock()
	err = tryUpdateSystemDns()
	systemDnsMu.Unlock()
	return err
}

// TryUpdateSystemDnsElapse will update system DNS if duration has elapsed since the last TryUpdateSystemDns1s call.
func TryUpdateSystemDnsElapse(k time.Duration) (err error) {
	systemDnsMu.Lock()
	defer systemDnsMu.Unlock()
	return tryUpdateSystemDnsElapse(k)
}

func tryUpdateSystemDnsElapse(k time.Duration) (err error) {
	if time.Now().Before(systemDnsNextUpdateAfter) {
		return fmt.Errorf("update too quickly")
	}
	err = tryUpdateSystemDns()
	if err != nil {
		return err
	}
	systemDnsNextUpdateAfter = time.Now().Add(k)
	return nil
}

func tryUpdateSystemDns() (err error) {
	dnsConf := dnsReadConfig("/etc/resolv.conf")
	systemDns = netip.AddrPort{}
	for _, s := range dnsConf.servers {
		ipPort := netip.MustParseAddrPort(s)
		if !ipPort.Addr().IsLoopback() {
			systemDns = ipPort
			break
		}
	}
	if !systemDns.IsValid() {
		systemDns = FallbackDns
	}
	return nil
}

func SystemDns() (dns netip.AddrPort, err error) {
	systemDnsMu.Lock()
	defer systemDnsMu.Unlock()
	if !systemDns.IsValid() {
		if err = tryUpdateSystemDns(); err != nil {
			return netip.AddrPort{}, err
		}
	}
	// To avoid environment changing.
	_ = tryUpdateSystemDnsElapse(5 * time.Second)
	return systemDns, nil
}

func ResolveHttp(client *http.Client, url *url.URL, msg *dnsmessage.Msg) error {
	// disable redirect https://github.com/daeuniverse/dae/pull/649#issuecomment-2379577896
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("do not use a server that will redirect, url: %v", url.String())
	}
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}

	// According https://datatracker.ietf.org/doc/html/rfc8484#section-4
	// msg id should set to 0 when transport over HTTPS for cache friendly.
	binary.BigEndian.PutUint16(data[0:2], 0)

	q := url.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(data))
	url.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Host = url.Host
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err = msg.Unpack(buf); err != nil {
		return err
	}
	return nil
}

func ResolveStream(stream io.ReadWriter, msg *dnsmessage.Msg, quic bool) error {
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}
	if quic {
		// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
		// msg id should set to 0 when transport over QUIC.
		// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
		binary.BigEndian.PutUint16(data[0:2], 0)
	}
	// We should write two byte length in the front of stream DNS request.
	buf := pool.Get(2 + len(data))
	defer buf.Put()
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[2:], data)
	_, err = stream.Write(buf)
	if err != nil {
		return oops.Wrapf(err, "failed to write DNS req")
	}

	// Read two byte length.
	if _, err = io.ReadFull(stream, buf[:2]); err != nil {
		return oops.Wrapf(err, "failed to read DNS resp payload length")
	}
	n := int(binary.BigEndian.Uint16(buf))
	// Try to reuse the buf.
	// if len(buf) < n {
	// 	buf.Put()
	// 	buf = pool.Get(n)
	// }
	var respBuf pool.PB
	if len(buf) < n {
		respBuf = pool.Get(n)
		defer respBuf.Put()
	} else {
		respBuf = buf
	}
	if _, err = io.ReadFull(stream, respBuf[:n]); err != nil {
		return oops.Wrapf(err, "failed to read DNS resp payload")
	}
	if err = msg.Unpack(respBuf[:n]); err != nil {
		return err
	}
	return nil
}

func ResolveUDP(conn netproxy.Conn, msg *dnsmessage.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}

	_ = conn.SetDeadline(time.Now().Add(consts.DefaultDNSTimeout))
	reqCtx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDNSTimeout)

	errCh := make(chan error, 1)
	go func() {
		// Send DNS request every seconds.
		for {
			_, err := conn.Write(data)
			if err != nil {
				errCh <- err
				return
			}
			select {
			case <-reqCtx.Done():
				errCh <- nil
				return
			case <-time.After(consts.DefaultRetryInterval):
			}
		}
	}()

	// Wait for response.
	respBuf := pool.GetFullCap(consts.EthernetMtu)
	defer respBuf.Put()
	n, err := conn.Read(respBuf)
	cancel()
	if err != nil {
		return err
	}
	if err = <-errCh; err != nil {
		return err
	}
	if err = msg.Unpack(respBuf[:n]); err != nil {
		return err
	}
	return nil
}

func ResolveNetip(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (addrs []netip.Addr, err error) {
	resources, err := resolve(ctx, d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		var (
			ip  netip.Addr
			okk bool
		)
		switch typ {
		case dnsmessage.TypeA:
			a, ok := ans.(*dnsmessage.A)
			if !ok {
				return nil, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.A)
		case dnsmessage.TypeAAAA:
			a, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				return nil, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.AAAA)
		}
		if !okk {
			continue
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

func ResolveNS(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, network string) (records []string, err error) {
	typ := dnsmessage.TypeNS
	resources, err := resolve(ctx, d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		ns, ok := ans.(*dnsmessage.NS)
		if !ok {
			return nil, ErrBadDnsAns
		}
		records = append(records, ns.Ns)
	}
	return records, nil
}

func ResolveSOA(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, network string) (records []string, err error) {
	typ := dnsmessage.TypeSOA
	resources, err := resolve(ctx, d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		ns, ok := ans.(*dnsmessage.SOA)
		if !ok {
			return nil, ErrBadDnsAns
		}
		records = append(records, ns.Ns)
	}
	return records, nil
}

func resolve(ctx context.Context, dialer netproxy.Dialer, server netip.AddrPort, host string, typ uint16, network string) (ans []dnsmessage.RR, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, oops.Wrapf(err, "parse magic network")
	}

	fqdn := dnsmessage.CanonicalName(host)
	switch typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if addr, err := netip.ParseAddr(host); err == nil {
			if (addr.Is4() || addr.Is4In6()) && typ == dnsmessage.TypeA {
				return []dnsmessage.RR{
					&dnsmessage.A{
						Hdr: dnsmessage.RR_Header{
							Name:   dnsmessage.CanonicalName(fqdn),
							Class:  dnsmessage.ClassINET,
							Ttl:    0,
							Rrtype: typ,
						},
						A: addr.AsSlice(),
					},
				}, nil
			} else if addr.Is6() && typ == dnsmessage.TypeAAAA {
				return []dnsmessage.RR{
					&dnsmessage.AAAA{
						Hdr: dnsmessage.RR_Header{
							Name:   dnsmessage.CanonicalName(fqdn),
							Class:  dnsmessage.ClassINET,
							Ttl:    0,
							Rrtype: typ,
						},
						AAAA: addr.AsSlice(),
					},
				}, nil
			}
			// MUST No record.
			return nil, nil
		}
	default:
	}
	// Build DNS req.
	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:               uint16(fastrand.Intn(math.MaxUint16 + 1)),
			Response:         false,
			Opcode:           0,
			Truncated:        false,
			RecursionDesired: true,
			Authoritative:    false,
		},
	}
	msg.SetQuestion(fqdn, typ)

	conn, err := dialer.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, oops.Wrapf(err, "DialContext")
	}

	if magicNetwork.Network == "tcp" {
		err = ResolveStream(conn, &msg, false)
	} else {
		err = ResolveUDP(conn, &msg)
	}
	if err != nil {
		return nil, err
	}
	return msg.Answer, nil
}
