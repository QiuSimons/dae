/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
)

// TODO: 现在的 ctx 是 dialCtx, 而不是完成 forward 流程的 ctx
type DnsForwarder interface {
	ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error
}

func newDnsForwarder(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	forwarder, err := func() (DnsForwarder, error) {
		switch dialArgument.networkType.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
				return &DoTCP{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_TLS:
				return &DoTLS{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_HTTPS:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: false}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return &DoUDP{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_QUIC:
				return &DoQ{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_H3:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: true}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArgument.networkType.L4Proto)
		}
	}()
	if err != nil {
		return nil, err
	}
	return forwarder, nil
}

type DoH struct {
	dns.Upstream
	dialArgument dialArgument
	http3        bool
}

func (d *DoH) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	var roundTripper http.RoundTripper
	if d.http3 {
		roundTripper = d.getHttp3RoundTripper()
	} else {
		roundTripper = d.getHttpRoundTripper()
	}
	client := &http.Client{
		Transport: roundTripper,
	}
	serverURL := &url.URL{
		Scheme: "https",
		Host:   d.dialArgument.Target.String(),
		Path:   d.Upstream.Path,
	}

	return netutils.ResolveHttp(client, serverURL, msg)
}

func (d *DoH) getHttpRoundTripper() *http.Transport {
	httpTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}

	return &httpTransport
}

func (d *DoH) getHttp3RoundTripper() *http3.RoundTripper {
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
			conn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			c, e := quic.DialEarly(ctx, conn, udpAddr, tlsCfg, cfg)
			return c, e
		},
	}
	return roundTripper
}

type DoQ struct {
	dns.Upstream
	dialArgument dialArgument
}

func (d *DoQ) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	qc, err := d.createConnection(ctx)
	if err != nil {
		return err
	}
	stream, err := qc.OpenStreamSync(ctx)
	if err != nil {
		return err
	}

	defer stream.Close()
	return netutils.ResolveStream(stream, msg, true)
}

func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {
	conn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
	qc, err := quic.DialEarly(ctx, conn, addr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	return qc, nil
}

type DoTLS struct {
	dns.Upstream
	dialArgument dialArgument
}

func (d *DoTLS) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	conn, err := d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
	if err != nil {
		return err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	if err = tlsConn.Handshake(); err != nil {
		return err
	}

	defer tlsConn.Close()
	return netutils.ResolveStream(conn, msg, false)
}

type DoTCP struct {
	dns.Upstream
	dialArgument dialArgument
}

// TODO: Connection reuse
func (d *DoTCP) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	conn, err := d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
	if err != nil {
		return err
	}

	defer conn.Close()
	return netutils.ResolveStream(conn, msg, false)
}

type DoUDP struct {
	dns.Upstream
	dialArgument dialArgument
}

// TODO: 在不导致放大的情况下尝试实现重传
func (d *DoUDP) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	conn, err := d.dialArgument.Dialer.DialContext(ctx, "udp", d.dialArgument.Target.String())
	if err != nil {
		return err
	}

	defer conn.Close()
	return netutils.ResolveUDP(conn, msg)
}
