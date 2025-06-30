/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
*/

package control

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	tc "github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
)

type DnsForwarder interface {
	ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error)
	Close() error
}

func newDnsForwarder(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	forwarder, err := func() (DnsForwarder, error) {
		switch dialArgument.l4proto {
		case consts.L4ProtoStr_TCP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
				return &DoTCP{MultiplexedDNSForwarder{
					upstream:     *upstream,
					dialer:       dialArgument.bestDialer,
					dialArgument: dialArgument,
					isTLS:        false,
				}}, nil
			case dns.UpstreamScheme_TLS:
				return &DoTLS{MultiplexedDNSForwarder{
					upstream:     *upstream,
					dialer:       dialArgument.bestDialer,
					dialArgument: dialArgument,
					isTLS:        true,
				}}, nil
			case dns.UpstreamScheme_HTTPS:
				return &DoH{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument, http3: false}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return &DoUDP{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_QUIC:
				return &DoQ{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_H3:
				return &DoH{Upstream: *upstream, Dialer: dialArgument.bestDialer, dialArgument: dialArgument, http3: true}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArgument.l4proto)
		}
	}()
	if err != nil {
		return nil, err
	}
	return forwarder, nil
}

type multiplexedDNSConn struct {
	mu      sync.Mutex
	conn    net.Conn // or tls.Conn, quic.EarlyConnection
	pending map[uint16]chan *dnsmessage.Msg
	closed  chan struct{}
	readErr error
}

func newMultiplexedDNSConn(conn net.Conn, readFunc func(io.Reader) (*dnsmessage.Msg, error)) *multiplexedDNSConn {
	m := &multiplexedDNSConn{
		conn:    conn,
		pending: make(map[uint16]chan *dnsmessage.Msg),
		closed:  make(chan struct{}),
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[multiplexedDNSConn] readLoop panic: %v\n", r)
			}
		}()
		m.readLoop(readFunc)
	}()
	return m
}

func (m *multiplexedDNSConn) send(ctx context.Context, req *dnsmessage.Msg, writeFunc func(io.Writer, *dnsmessage.Msg) error) (*dnsmessage.Msg, error) {
	respCh := make(chan *dnsmessage.Msg, 1)
	m.mu.Lock()
	if m.readErr != nil {
		m.mu.Unlock()
		return nil, m.readErr
	}
	m.pending[req.Id] = respCh
	defer m.mu.Unlock()

	if err := writeFunc(m.conn, req); err != nil {
		delete(m.pending, req.Id)
		return nil, err
	}

	m.mu.Unlock()

	select {
	case resp := <-respCh:
		return resp, nil
	case <-ctx.Done():
		m.removePending(req.Id)
		return nil, ctx.Err()
	case <-m.closed:
		m.removePending(req.Id)
		return nil, m.readErr
	}
}

func (m *multiplexedDNSConn) removePending(id uint16) {
	m.mu.Lock()
	delete(m.pending, id)
	m.mu.Unlock()
}

func (m *multiplexedDNSConn) readLoop(readFunc func(io.Reader) (*dnsmessage.Msg, error)) {
	for {
		resp, err := readFunc(m.conn)
		if err != nil {
			m.mu.Lock()
			m.readErr = err
			for _, ch := range m.pending {
				select {
				case <-ch:
					// already closed or drained
				default:
					close(ch)
				}
			}
			m.pending = make(map[uint16]chan *dnsmessage.Msg)
			select {
			case <-m.closed:
				// already closed
			default:
				close(m.closed)
			}
			m.mu.Unlock()
			return
		}
		m.mu.Lock()
		ch, ok := m.pending[resp.Id]
		if ok {
			ch <- resp
			delete(m.pending, resp.Id)
		}
		m.mu.Unlock()
	}
}

type MultiplexedDNSForwarder struct {
	upstream        dns.Upstream
	dialer          netproxy.Dialer
	dialArgument    dialArgument
	multiplexedConn *multiplexedDNSConn
	connMu          sync.Mutex
	isTLS           bool
	nextID          uint32
}

func (f *MultiplexedDNSForwarder) allocUniqueID() uint16 {
	id := atomic.AddUint32(&f.nextID, 1)
	if id == 0 {
		id = atomic.AddUint32(&f.nextID, 1)
	}
	return uint16(id)
}

func (f *MultiplexedDNSForwarder) ensureConn() error {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	if f.multiplexedConn != nil && f.multiplexedConn.readErr == nil {
		return nil
	}

	// Add timeout to prevent infinite waiting
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := f.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("tcp", f.dialArgument.mark, f.dialArgument.mptcp),
		f.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return fmt.Errorf("[MultiplexedDNSForwarder] DialContext failed: %w", err)
	}

	// Try to convert netproxy.Conn to net.Conn
	var netConn net.Conn
	if nc, ok := conn.(net.Conn); ok {
		netConn = nc
	} else {
		// If direct conversion fails, try to wrap with FakeNetConn
		netConn = &netproxy.FakeNetConn{Conn: conn}
		// 检查FakeNetConn是否实现了必要接口，否则报错
		if netConn == nil {
			return fmt.Errorf("[MultiplexedDNSForwarder] conn cannot be converted to net.Conn nor wrapped by FakeNetConn")
		}
	}

	if f.isTLS {
		tlsConn := tls.Client(netConn, &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         f.upstream.Hostname,
		})
		if err = tlsConn.Handshake(); err != nil {
			netConn.Close()
			return fmt.Errorf("[MultiplexedDNSForwarder] TLS handshake failed: %w", err)
		}
		f.multiplexedConn = newMultiplexedDNSConn(tlsConn, readStreamDNS)
	} else {
		f.multiplexedConn = newMultiplexedDNSConn(netConn, readStreamDNS)
	}
	return nil
}

func (f *MultiplexedDNSForwarder) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if err := f.ensureConn(); err != nil {
		return nil, err
	}
	var req dnsmessage.Msg
	if err := req.Unpack(data); err != nil {
		return nil, err
	}
	req.Id = f.allocUniqueID()
	return f.multiplexedConn.send(ctx, &req, writeStreamDNS)
}

func (f *MultiplexedDNSForwarder) Close() error {
	f.connMu.Lock()
	defer f.connMu.Unlock()
	if f.multiplexedConn != nil && f.multiplexedConn.conn != nil {
		return f.multiplexedConn.conn.Close()
	}
	return nil
}

type DoH struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	http3        bool
	client       *http.Client
}

func (d *DoH) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if d.client == nil {
		d.client = d.getClient()
	}
	msg, err := sendHttpDNS(d.client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
	if err != nil {
		// If failed to send DNS request, we should try to create a new client.
		d.client = d.getClient()
		msg, err = sendHttpDNS(d.client, d.dialArgument.bestTarget.String(), &d.Upstream, data)
		if err != nil {
			return nil, err
		}
		return msg, nil
	}
	return msg, nil
}

func (d *DoH) getClient() *http.Client {
	var roundTripper http.RoundTripper
	if d.http3 {
		roundTripper = d.getHttp3RoundTripper()
	} else {
		roundTripper = d.getHttpRoundTripper()
	}

	return &http.Client{
		Transport: roundTripper,
	}
}

func (d *DoH) getHttpRoundTripper() *http.Transport {
	httpTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("tcp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: conn}, nil
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
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
			conn, err := d.dialArgument.bestDialer.DialContext(
				ctx,
				common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
				d.dialArgument.bestTarget.String(),
			)
			if err != nil {
				return nil, err
			}

			// Safely convert to PacketConn
			packetConn, ok := conn.(netproxy.PacketConn)
			if !ok {
				return nil, fmt.Errorf("connection does not implement netproxy.PacketConn")
			}

			fakePkt := netproxy.NewFakeNetPacketConn(packetConn, net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
			c, e := quic.DialEarly(ctx, fakePkt, udpAddr, tlsCfg, cfg)
			return c, e
		},
	}
	return roundTripper
}

func (d *DoH) Close() error {
	return nil
}

type DoQ struct {
	dns.Upstream
	netproxy.Dialer
	dialArgument dialArgument
	connMu       sync.Mutex
	connection   quic.EarlyConnection
}

func (d *DoQ) ensureConn(ctx context.Context) error {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if d.connection != nil && d.connection.Context().Err() == nil {
		return nil
	}
	qc, err := d.createConnection(ctx)
	if err != nil {
		return err
	}
	d.connection = qc
	return nil
}

func (d *DoQ) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	if err := d.ensureConn(ctx); err != nil {
		return nil, err
	}
	// Each request uses an independent stream
	stream, err := d.connection.OpenStreamSync(ctx)
	if err != nil {
		// The connection may be broken, try to reconnect
		d.connMu.Lock()
		d.connection = nil
		d.connMu.Unlock()
		if err := d.ensureConn(ctx); err != nil {
			return nil, err
		}
		stream, err = d.connection.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
	}
	// According to RFC9250, the messageId of QUIC DNS requests must be 0
	if len(data) >= 2 {
		data[0] = 0
		data[1] = 0
	}
	msg, err := sendStreamDNS(stream, data)
	_ = stream.Close() // Only close after receiving the full response
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {

	udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}

	// Safely convert to PacketConn
	packetConn, ok := conn.(netproxy.PacketConn)
	if !ok {
		return nil, fmt.Errorf("connection does not implement netproxy.PacketConn")
	}

	fakePkt := netproxy.NewFakeNetPacketConn(packetConn, net.UDPAddrFromAddrPort(tc.GetUniqueFakeAddrPort()), udpAddr)
	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.dialArgument.bestTarget)
	qc, err := quic.DialEarly(ctx, fakePkt, addr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}
	return qc, nil

}

func (d *DoQ) Close() error {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if d.connection != nil {
		return d.connection.CloseWithError(0, "closed")
	}
	return nil
}

type DoTLS struct{ MultiplexedDNSForwarder }
type DoTCP struct{ MultiplexedDNSForwarder }

func sendHttpDNS(client *http.Client, target string, upstream *dns.Upstream, data []byte) (respMsg *dnsmessage.Msg, err error) {
	// disable redirect https://github.com/daeuniverse/dae/pull/649#issuecomment-2379577896
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("do not use a server that will redirect, upstream: %v", upstream.String())
	}
	serverURL := url.URL{
		Scheme: "https",
		Host:   target,
		Path:   upstream.Path,
	}
	q := serverURL.Query()
	// According https://datatracker.ietf.org/doc/html/rfc8484#section-4
	// msg id should set to 0 when transport over HTTPS for cache friendly.
	binary.BigEndian.PutUint16(data[0:2], 0)
	q.Set("dns", base64.RawURLEncoding.EncodeToString(data))
	serverURL.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, serverURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Host = upstream.Hostname
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf); err != nil {
		return nil, err
	}
	return &msg, nil
}

func sendStreamDNS(stream io.ReadWriter, data []byte) (respMsg *dnsmessage.Msg, err error) {
	// We should write two byte length in the front of stream DNS request.
	bReq := pool.Get(2 + len(data))
	defer pool.Put(bReq)
	binary.BigEndian.PutUint16(bReq, uint16(len(data)))
	copy(bReq[2:], data)
	_, err = stream.Write(bReq)
	if err != nil {
		return nil, fmt.Errorf("failed to write DNS req: %w", err)
	}

	// Read two byte length.
	if _, err = io.ReadFull(stream, bReq[:2]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(bReq))
	// Try to reuse the buf.
	var buf []byte
	if len(bReq) < respLen {
		buf = pool.Get(respLen)
		defer pool.Put(buf)
	} else {
		buf = bReq
	}
	var n int
	if n, err = io.ReadFull(stream, buf[:respLen]); err != nil {
		return nil, fmt.Errorf("failed to read DNS resp payload: %w", err)
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}

func readStreamDNS(r io.Reader) (*dnsmessage.Msg, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(b))
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var msg dnsmessage.Msg
	if err := msg.Unpack(buf); err != nil {
		return nil, err
	}
	return &msg, nil
}

func writeStreamDNS(w io.Writer, req *dnsmessage.Msg) error {
	buf, err := req.Pack()
	if err != nil {
		return err
	}
	b := make([]byte, 2+len(buf))
	binary.BigEndian.PutUint16(b, uint16(len(buf)))
	copy(b[2:], buf)
	_, err = w.Write(b)
	return err
}

// High-performance UDP task pool for DoUDP only
var dnsUDPTaskPool = newDnsUDPTaskPool()

type DnsUDPTask = func()

type DnsUDPTaskQueue struct {
	ch    chan DnsUDPTask
	close chan struct{}
}

type DnsUDPTaskPool struct {
	mu sync.RWMutex
	m  map[string]*DnsUDPTaskQueue
}

func newDnsUDPTaskPool() *DnsUDPTaskPool {
	return &DnsUDPTaskPool{m: make(map[string]*DnsUDPTaskQueue)}
}

// EmitTask: ensure tasks with the same key are executed in order
func (p *DnsUDPTaskPool) EmitTask(key string, task DnsUDPTask) {
	if task == nil {
		return
	}
	p.mu.RLock()
	q, ok := p.m[key]
	p.mu.RUnlock()
	if ok {
		select {
		case q.ch <- task:
		default:
			// drop if full
		}
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if q, ok := p.m[key]; ok {
		select {
		case q.ch <- task:
		default:
		}
		return
	}
	ch := make(chan DnsUDPTask, 512)
	closeCh := make(chan struct{})
	q = &DnsUDPTaskQueue{ch: ch, close: closeCh}
	p.m[key] = q
	go func() {
		for {
			select {
			case t := <-ch:
				if t != nil {
					func() {
						defer func() { _ = recover() }()
						t()
					}()
				}
			case <-closeCh:
				return
			}
		}
	}()
	select {
	case ch <- task:
	default:
	}
}

type DoUDP struct {
	Upstream     dns.Upstream
	Dialer       netproxy.Dialer
	dialArgument dialArgument
	conn         netproxy.Conn
}

func (d *DoUDP) ForwardDNS(ctx context.Context, data []byte) (*dnsmessage.Msg, error) {
	conn, err := d.dialArgument.bestDialer.DialContext(
		ctx,
		common.MagicNetwork("udp", d.dialArgument.mark, d.dialArgument.mptcp),
		d.dialArgument.bestTarget.String(),
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	timeout := 5 * time.Second
	_ = conn.SetDeadline(time.Now().Add(timeout))
	dnsReqCtx, cancelDnsReqCtx := context.WithTimeout(context.TODO(), timeout)
	defer cancelDnsReqCtx()

	respCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	// 只发送一次数据包
	go func() {
		_, err := conn.Write(data)
		if err != nil {
			errCh <- err
			return
		}
	}()

	// Read response
	go func() {
		respBuf := pool.GetFullCap(consts.EthernetMtu)
		defer pool.Put(respBuf)
		n, err := conn.Read(respBuf)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- respBuf[:n]
	}()

	select {
	case <-dnsReqCtx.Done():
		return nil, fmt.Errorf("timeout waiting for DNS response")
	case err := <-errCh:
		return nil, err
	case resp := <-respCh:
		var msg dnsmessage.Msg
		if err := msg.Unpack(resp); err != nil {
			return nil, err
		}
		return &msg, nil
	}
}

func (d *DoUDP) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
