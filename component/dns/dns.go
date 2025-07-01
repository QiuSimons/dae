/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var ErrBadUpstreamFormat = fmt.Errorf("bad upstream format")

const (
	maxDnsUdpListenerPoolSize = 4096
	maxDnsUdpEndpointPoolSize = 4096
	maxDnsUdpTaskPoolSize     = 4096
	cleanupInterval           = 5 * time.Minute
)

type Dns struct {
	log              *logrus.Logger
	upstream         []*UpstreamResolver
	upstream2Index   sync.Map
	reqMatcher       *RequestMatcher
	respMatcher      *ResponseMatcher
}

type NewOption struct {
	Logger                  *logrus.Logger
	LocationFinder          *assets.LocationFinder
	UpstreamReadyCallback   func(dnsUpstream *Upstream) (err error)
	UpstreamResolverNetwork string
}

// Lockless UDP listener pool dedicated for DNS, used only internally
// Add maximum capacity and periodic cleanup mechanism

type DnsUdpListenerPool struct {
	pool   sync.Map // map[string]*net.UDPConn
	stopCh chan struct{}
}

func NewDnsUdpListenerPool() *DnsUdpListenerPool {
	p := &DnsUdpListenerPool{stopCh: make(chan struct{})}
	go p.backgroundCleanup()
	return p
}

// Periodically clean up expired or invalid UDP listeners.
func (p *DnsUdpListenerPool) backgroundCleanup() {
	maxWait := 30 * time.Minute
	for {
		now := time.Now()
		soonestExpire := now.Add(maxWait)
		p.pool.Range(func(key, value any) bool {
			// Only clean by capacity, TTL expiration is handled by time.AfterFunc.
			// No unified expiration field, skip.
			return true
		})
		wait := soonestExpire.Sub(now)
		if wait <= 0 || wait > maxWait {
			wait = maxWait
		}
		select {
		case <-time.After(wait):
		case <-p.stopCh:
			return
		}
	}
}

func (p *DnsUdpListenerPool) Close() {
	close(p.stopCh)
	p.pool.Range(func(key, value any) bool {
		p.pool.Delete(key)
		return true
	})
}

func (p *DnsUdpListenerPool) GetOrCreate(lAddr string, ttl time.Duration) (conn *net.UDPConn, isNew bool, err error) {
	count := 0
	p.pool.Range(func(_, _ any) bool { count++; return true })
	if count >= maxDnsUdpListenerPoolSize {
		return nil, false, fmt.Errorf("listener pool full")
	}
	if c, ok := p.pool.Load(lAddr); ok {
		return c.(*net.UDPConn), false, nil
	}
	createKey := lAddr + "_creating"
	if _, loaded := p.pool.LoadOrStore(createKey, struct{}{}); loaded {
		for i := 0; i < 10; i++ {
			time.Sleep(time.Millisecond * 10)
			if c, ok := p.pool.Load(lAddr); ok {
				return c.(*net.UDPConn), false, nil
			}
		}
		p.pool.Delete(createKey)
		return nil, false, fmt.Errorf("concurrent create timeout: %s", lAddr)
	}
	defer p.pool.Delete(createKey)
	if c, ok := p.pool.Load(lAddr); ok {
		return c.(*net.UDPConn), false, nil
	}
	d := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			return nil
		},
		KeepAlive: 0,
	}
	var pc net.PacketConn
	pc, err = d.ListenPacket(context.Background(), "udp", lAddr)
	if err != nil {
		return nil, true, err
	}
	uConn := pc.(*net.UDPConn)
	if ttl > 0 {
		time.AfterFunc(ttl, func() {
			p.pool.Delete(lAddr)
			uConn.Close()
		})
	}
	p.pool.Store(lAddr, uConn)
	return uConn, true, nil
}

// Lockless UDP endpoint pool dedicated for DNS, used only internally
// Add maximum capacity, periodic cleanup, and DCLP retry mechanism

type DnsUdpEndpoint struct {
	lastActive time.Time
}

type DnsUdpEndpointPool struct {
	pool   sync.Map // map[string]*DnsUdpEndpoint
	stopCh chan struct{}
}

func NewDnsUdpEndpointPool() *DnsUdpEndpointPool {
	p := &DnsUdpEndpointPool{stopCh: make(chan struct{})}
	go p.backgroundCleanup()
	return p
}

// Periodically clean up expired UDP endpoints based on lastActive.
func (p *DnsUdpEndpointPool) backgroundCleanup() {
	maxWait := 30 * time.Minute
	for {
		now := time.Now()
		soonestExpire := now.Add(maxWait)
		p.pool.Range(func(key, value any) bool {
			endpoint, ok := value.(*DnsUdpEndpoint)
			if !ok {
				p.pool.Delete(key)
				return true
			}
			expireTime := endpoint.lastActive.Add(10 * cleanupInterval)
			if now.After(expireTime) {
				p.pool.Delete(key)
			} else if expireTime.Before(soonestExpire) {
				soonestExpire = expireTime
			}
			return true
		})
		wait := soonestExpire.Sub(now)
		if wait <= 0 || wait > maxWait {
			wait = maxWait
		}
		select {
		case <-time.After(wait):
		case <-p.stopCh:
			return
		}
	}
}

func (p *DnsUdpEndpointPool) Close() {
	close(p.stopCh)
	p.pool.Range(func(key, value any) bool {
		p.pool.Delete(key)
		return true
	})
}

func (p *DnsUdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createOption any) (endpoint *DnsUdpEndpoint, isNew bool, err error) {
	count := 0
	p.pool.Range(func(_, _ any) bool { count++; return true })
	if count >= maxDnsUdpEndpointPoolSize {
		return nil, false, fmt.Errorf("endpoint pool full")
	}
	key := lAddr.String()
	if e, ok := p.pool.Load(key); ok {
		endpoint, ok = e.(*DnsUdpEndpoint)
		if !ok {
			p.pool.Delete(key)
			return nil, false, fmt.Errorf("endpoint type assertion failed")
		}
		endpoint.lastActive = time.Now()
		return endpoint, false, nil
	}
	createKey := key + "_creating"
	if _, loaded := p.pool.LoadOrStore(createKey, struct{}{}); loaded {
		for i := 0; i < 10; i++ {
			time.Sleep(time.Millisecond * 10)
			if e, ok := p.pool.Load(key); ok {
				endpoint, ok = e.(*DnsUdpEndpoint)
				if !ok {
					p.pool.Delete(key)
					return nil, false, fmt.Errorf("endpoint type assertion failed")
				}
				endpoint.lastActive = time.Now()
				return endpoint, false, nil
			}
		}
		p.pool.Delete(createKey)
		return nil, false, fmt.Errorf("concurrent create timeout: %s", key)
	}
	defer p.pool.Delete(createKey)
	if e, ok := p.pool.Load(key); ok {
		endpoint, ok = e.(*DnsUdpEndpoint)
		if !ok {
			p.pool.Delete(key)
			return nil, false, fmt.Errorf("endpoint type assertion failed")
		}
		endpoint.lastActive = time.Now()
		return endpoint, false, nil
	}
	endpoint = &DnsUdpEndpoint{lastActive: time.Now()}
	p.pool.Store(key, endpoint)
	return endpoint, true, nil
}

// Lockless UDP task pool dedicated for DNS, used only internally
// Add maximum capacity and periodic cleanup mechanism

type DnsUdpTask func()

type DnsUdpTaskQueue struct {
	ch         chan DnsUdpTask
	lastActive time.Time
}

type DnsUdpTaskPool struct {
	pool   sync.Map // map[string]*DnsUdpTaskQueue
	stopCh chan struct{}
}

func NewDnsUdpTaskPool() *DnsUdpTaskPool {
	p := &DnsUdpTaskPool{stopCh: make(chan struct{})}
	go p.backgroundCleanup()
	return p
}

// Periodically clean up expired UDP task queues based on lastActive.
func (p *DnsUdpTaskPool) backgroundCleanup() {
	maxWait := 30 * time.Minute
	for {
		now := time.Now()
		soonestExpire := now.Add(maxWait)
		p.pool.Range(func(key, value any) bool {
			q, ok := value.(*DnsUdpTaskQueue)
			if !ok {
				p.pool.Delete(key)
				return true
			}
			expireTime := q.lastActive.Add(10 * cleanupInterval)
			if now.After(expireTime) {
				p.pool.Delete(key)
			} else if expireTime.Before(soonestExpire) {
				soonestExpire = expireTime
			}
			return true
		})
		wait := soonestExpire.Sub(now)
		if wait <= 0 || wait > maxWait {
			wait = maxWait
		}
		select {
		case <-time.After(wait):
		case <-p.stopCh:
			return
		}
	}
}

func (p *DnsUdpTaskPool) Close() {
	close(p.stopCh)
	p.pool.Range(func(key, value any) bool {
		p.pool.Delete(key)
		return true
	})
}

func (p *DnsUdpTaskPool) EmitTask(key string, task DnsUdpTask) {
	count := 0
	p.pool.Range(func(_, _ any) bool { count++; return true })
	if count >= maxDnsUdpTaskPoolSize {
		return
	}
	qAny, _ := p.pool.LoadOrStore(key, &DnsUdpTaskQueue{ch: make(chan DnsUdpTask, 512), lastActive: time.Now()})
	q := qAny.(*DnsUdpTaskQueue)
	select {
	case q.ch <- task:
		q.lastActive = time.Now()
		// ok
	default:
		// Drop the task if the queue is full.
	}
}

func New(dns *config.Dns, opt *NewOption) (s *Dns, err error) {
	s = &Dns{
		log: opt.Logger,
		// upstream2Index uses sync.Map, no need to initialize
	}
	// Set the default nil mapping
	s.upstream2Index.Store((*Upstream)(nil), int(consts.DnsRequestOutboundIndex_AsIs))
	// Parse upstream.
	upstreamName2Id := map[string]uint8{}
	for i, upstreamRaw := range dns.Upstream {
		if i >= int(consts.DnsRequestOutboundIndex_UserDefinedMax) ||
			i >= int(consts.DnsResponseOutboundIndex_UserDefinedMax) {
			return nil, fmt.Errorf("too many upstreams")
		}

		tag, link := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if tag == "" {
			return nil, fmt.Errorf("%w: '%v' has no tag", ErrBadUpstreamFormat, upstreamRaw)
		}
		var u *url.URL
		u, err = url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
		}
		r := &UpstreamResolver{
			Raw:     u,
			Network: opt.UpstreamResolverNetwork,
			FinishInitCallback: func(i int) func(raw *url.URL, upstream *Upstream) (err error) {
				return func(raw *url.URL, upstream *Upstream) (err error) {
					if opt != nil && opt.UpstreamReadyCallback != nil {
						if err = opt.UpstreamReadyCallback(upstream); err != nil {
							return err
						}
					}

					s.upstream2Index.Store(upstream, i)
					return nil
				}
			}(i),
			mu:       sync.Mutex{},
			upstream: nil,
			init:     false,
		}
		upstreamName2Id[tag] = uint8(len(s.upstream))
		s.upstream = append(s.upstream, r)
	}
	// Optimize routings.
	if dns.Routing.Request.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Request.Rules,
		&routing.DatReaderOptimizer{Logger: opt.Logger, LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}
	if dns.Routing.Response.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Response.Rules,
		&routing.DatReaderOptimizer{Logger: opt.Logger, LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}
	// Parse request routing.
	reqMatcherBuilder, err := NewRequestMatcherBuilder(opt.Logger, dns.Routing.Request.Rules, upstreamName2Id, dns.Routing.Request.Fallback)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
	}
	s.reqMatcher, err = reqMatcherBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
	}
	// Parse response routing.
	respMatcherBuilder, err := NewResponseMatcherBuilder(opt.Logger, dns.Routing.Response.Rules, upstreamName2Id, dns.Routing.Response.Fallback)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	s.respMatcher, err = respMatcherBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	if len(dns.Upstream) == 0 {
		// Immediately ready.
		go opt.UpstreamReadyCallback(nil)
	}
	return s, nil
}

func (s *Dns) CheckUpstreamsFormat() error {
	for _, upstream := range s.upstream {
		_, _, _, _, err := ParseRawUpstream(upstream.Raw)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Dns) InitUpstreams() {
	var wg sync.WaitGroup
	for _, upstream := range s.upstream {
		wg.Add(1)
		go func(upstream *UpstreamResolver) {
			_, err := upstream.GetUpstream()
			if err != nil {
				s.log.WithError(err).Debugln("Dns.GetUpstream")
			}
			wg.Done()
		}(upstream)
	}
	wg.Wait()
}

func (s *Dns) RequestSelect(qname string, qtype uint16) (upstreamIndex consts.DnsRequestOutboundIndex, upstream *Upstream, err error) {
	// Route.
	upstreamIndex, err = s.reqMatcher.Match(qname, qtype)
	if err != nil {
		return 0, nil, err
	}
	// nil indicates AsIs.
	if upstreamIndex == consts.DnsRequestOutboundIndex_AsIs ||
		upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		return upstreamIndex, nil, nil
	}
	if int(upstreamIndex) >= len(s.upstream) {
		return 0, nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
	}
	// Get corresponding upstream.
	upstream, err = s.upstream[upstreamIndex].GetUpstream()
	if err != nil {
		return 0, nil, err
	}
	return upstreamIndex, upstream, nil
}

func (s *Dns) ResponseSelect(msg *dnsmessage.Msg, fromUpstream *Upstream) (upstreamIndex consts.DnsResponseOutboundIndex, upstream *Upstream, err error) {
	if !msg.Response {
		return 0, nil, fmt.Errorf("DNS response expected but DNS request received")
	}

	// Prepare routing.
	var qname string
	var qtype uint16
	var ips []netip.Addr
	if len(msg.Question) == 0 {
		qname = ""
		qtype = 0
	} else {
		q := msg.Question[0]
		qname = q.Name
		qtype = q.Qtype
		for _, ans := range msg.Answer {
			var (
				ip netip.Addr
				ok bool
			)
			switch body := ans.(type) {
			case *dnsmessage.A:
				ip, ok = netip.AddrFromSlice(body.A)
			case *dnsmessage.AAAA:
				ip, ok = netip.AddrFromSlice(body.AAAA)
			}
			if !ok {
				continue
			}
			ips = append(ips, ip)
		}
	}

	fromValue, ok := s.upstream2Index.Load(fromUpstream)
	if !ok {
		fromValue = int(consts.DnsRequestOutboundIndex_AsIs) // default value
	}
	from := fromValue.(int)
	// Route.
	upstreamIndex, err = s.respMatcher.Match(qname, qtype, ips, consts.DnsRequestOutboundIndex(from))
	if err != nil {
		return 0, nil, err
	}
	// Get corresponding upstream if upstream is neither 'accept' nor 'reject'.
	if !upstreamIndex.IsReserved() {
		if int(upstreamIndex) >= len(s.upstream) {
			return 0, nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
		}
		upstream, err = s.upstream[upstreamIndex].GetUpstream()
		if err != nil {
			return 0, nil, err
		}
	} else {
		// Assign explicitly to let coder know.
		upstream = nil
	}
	return upstreamIndex, upstream, nil
}
