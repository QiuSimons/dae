/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

const (
	MaxDnsLookupDepth  = 3
	minFirefoxCacheTtl = 120
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	ErrUnsupportedQuestionType = fmt.Errorf("unsupported question type")
)

var (
	UnspecifiedAddressA    = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA = netip.MustParseAddr("::")
)

type DnsControllerOption struct {
	Log                   *logrus.Logger
	CacheAccessCallback   func(cache *DnsCache) (err error)
	CacheRemoveCallback   func(cache *DnsCache) (err error)
	NewCache              func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	BestDialerChooser     func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	TimeoutExceedCallback func(dialArgument *dialArgument, err error)
	IpVersionPrefer       int
	FixedDomainTtl        map[string]int
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	log                 *logrus.Logger
	cacheAccessCallback func(cache *DnsCache) (err error)
	cacheRemoveCallback func(cache *DnsCache) (err error)
	newCache            func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	bestDialerChooser   func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	// timeoutExceedCallback is used to report this dialer is broken for the NetworkType
	timeoutExceedCallback func(dialArgument *dialArgument, err error)

	fixedDomainTtl map[string]int
	// Use sync.Map instead of mutex+map to reduce lock contention
	dnsCache          sync.Map // map[string]*DnsCache
	dnsForwarderCache sync.Map // map[dnsForwarderKey]DnsForwarder

	forwarderManager *DnsForwarderManager // 保留转发器管理器

	// 缓存清理相关
	stopCleanup chan struct{}

	// 优化的清理参数
	cleanupStats struct {
		sync.RWMutex     // 使用读写锁减少竞争
		lastCleanupTime  time.Time
		lastCleanupCount int
		avgCleanupCount  float64
		cacheSize        int
		expiredRatio     float64
		nextCleanupTime  time.Time // 下次清理时间
	}

	// 清理控制
	cleanupConfig struct {
		sync.RWMutex
		enabled     bool
		maxInterval time.Duration
		minInterval time.Duration
		batchSize   int // 每次清理的最大批次数
	}
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	// Parse ip version preference.
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	c = &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		log:                   option.Log,
		cacheAccessCallback:   option.CacheAccessCallback,
		cacheRemoveCallback:   option.CacheRemoveCallback,
		newCache:              option.NewCache,
		bestDialerChooser:     option.BestDialerChooser,
		timeoutExceedCallback: option.TimeoutExceedCallback,

		fixedDomainTtl: option.FixedDomainTtl,
		// Use sync.Map, no need to initialize
		forwarderManager: NewDnsForwarderManager(), // new initialization
		stopCleanup:      make(chan struct{}),
	}

	// 初始化清理配置
	c.cleanupConfig.enabled = true
	c.cleanupConfig.maxInterval = 30 * time.Minute
	c.cleanupConfig.minInterval = 2 * time.Minute
	c.cleanupConfig.batchSize = 100 // 每次最多清理100个

	// 初始化清理统计
	c.cleanupStats.lastCleanupTime = time.Now()
	c.cleanupStats.nextCleanupTime = time.Now().Add(c.cleanupConfig.minInterval)
	c.cleanupStats.avgCleanupCount = 0

	// 修复：确保DNS路由配置有效
	if routing == nil {
		return nil, fmt.Errorf("DNS routing configuration is nil")
	}

	// 启动优化的缓存清理协程
	go c.optimizedCleanupExpiredCache()

	return c, nil
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	// To fqdn.
	return dnsmessage.CanonicalName(qname) + strconv.Itoa(int(qtype))
}

func (c *DnsController) RemoveDnsRespCache(cacheKey string) {
	cacheValue, ok := c.dnsCache.Load(cacheKey)
	if ok {
		cache, ok := cacheValue.(*DnsCache)
		if ok && c.cacheRemoveCallback != nil {
			_ = c.cacheRemoveCallback(cache)
		}
	}
	c.dnsCache.Delete(cacheKey)
}

func (c *DnsController) LookupDnsRespCache(cacheKey string, ignoreFixedTtl bool) (cache *DnsCache) {
	cacheValue, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		return nil
	}
	cache, ok = cacheValue.(*DnsCache)
	if !ok {
		return nil
	}
	var deadline time.Time
	if !ignoreFixedTtl {
		deadline = cache.Deadline
	} else {
		deadline = cache.OriginalDeadline
	}
	if time.Now().After(deadline) {
		return nil
	}
	// Do not update eBPF on cache hit
	return cache
}

// LookupDnsRespCache_ handle DNS resp in place.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) (resp []byte) {
	cache := c.LookupDnsRespCache(cacheKey, ignoreFixedTtl)
	if cache != nil {
		cache.FillInto(msg)
		msg.Compress = true
		b, err := msg.Pack()
		if err != nil {
			c.log.Warnf("failed to pack: %v", err)
			return nil
		}
		return b
	}
	return nil
}

// NormalizeAndCacheDnsResp_ handle DNS resp in place.
func (c *DnsController) NormalizeAndCacheDnsResp_(msg *dnsmessage.Msg) (err error) {
	// Check healthy resp.
	if !msg.Response || len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]

	// Check suc resp.
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return nil
	}

	// Get TTL.
	var ttl uint32
	for i := range msg.Answer {
		if ttl == 0 {
			ttl = msg.Answer[i].Header().Ttl
			break
		}
	}
	if ttl == 0 {
		// It seems no answers (NXDomain).
		ttl = minFirefoxCacheTtl
	}

	// Check req type.
	switch q.Qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Set ttl.
	for i := range msg.Answer {
		// Set TTL = zero. This requests applications must resend every request.
		// However, it may be not defined in the standard.
		msg.Answer[i].Header().Ttl = 0
	}

	// Check if request A/AAAA record.
	var reqIpRecord bool
loop:
	for i := range msg.Question {
		switch msg.Question[i].Qtype {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			reqIpRecord = true
			break loop
		}
	}
	if !reqIpRecord {
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Update DnsCache.
	if err = c.updateDnsCache(msg, ttl, &q); err != nil {
		return err
	}
	// Pack to get newData.
	return nil
}

func (c *DnsController) updateDnsCache(msg *dnsmessage.Msg, ttl uint32, q *dnsmessage.Question) error {
	// Update DnsCache.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"_qname": q.Name,
			"rcode":  msg.Rcode,
			"ans":    FormatDnsRsc(msg.Answer),
		}).Tracef("Update DNS record cache")
	}

	if err := c.UpdateDnsCacheTtl(q.Name, q.Qtype, msg.Answer, int(ttl)); err != nil {
		return err
	}
	return nil
}

type daedlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time)

func (c *DnsController) __updateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadlineFunc daedlineFunc) (err error) {
	var fqdn string
	if strings.HasSuffix(host, ".") {
		fqdn = strings.ToLower(host)
		host = host[:len(host)-1]
	} else {
		fqdn = dnsmessage.CanonicalName(host)
	}
	// Bypass pure IP.
	if _, err = netip.ParseAddr(host); err == nil {
		return nil
	}

	now := time.Now()
	deadline, originalDeadline := deadlineFunc(now, host)

	cacheKey := c.cacheKey(fqdn, dnsTyp)

	// Create a new cache entry instead of modifying the existing one to avoid data races.
	cache, err := c.newCache(fqdn, answers, deadline, originalDeadline)
	if err != nil {
		return err
	}

	// Atomically update the cache
	c.dnsCache.Store(cacheKey, cache)

	// 异步执行回调函数，避免阻塞DNS处理
	if c.cacheAccessCallback != nil {
		go func() {
			if err := c.cacheAccessCallback(cache); err != nil {
				// 记录错误但不阻塞主流程
				c.log.WithError(err).Warnf("Cache access callback failed for %v", cacheKey)
			}
		}()
	}

	return nil
}

func (c *DnsController) UpdateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadline time.Time) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		if fixedTtl, ok := c.fixedDomainTtl[host]; ok {
			/// NOTICE: Cannot set TTL accurately.
			if now.Sub(deadline).Seconds() > float64(fixedTtl) {
				deadline := now.Add(time.Duration(fixedTtl) * time.Second)
				return deadline, deadline
			}
		}
		return deadline, deadline
	})
}

func (c *DnsController) UpdateDnsCacheTtl(host string, dnsTyp uint16, answers []dnsmessage.RR, ttl int) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		originalDeadline = now.Add(time.Duration(ttl) * time.Second)
		if fixedTtl, ok := c.fixedDomainTtl[host]; ok {
			return now.Add(time.Duration(fixedTtl) * time.Second), originalDeadline
		} else {
			return originalDeadline, originalDeadline
		}
	})
}

type udpRequest struct {
	realSrc       netip.AddrPort
	realDst       netip.AddrPort
	src           netip.AddrPort
	lConn         *net.UDPConn
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	bestDialer   *dialer.Dialer
	bestOutbound *outbound.DialerGroup
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

type dnsForwarderKey struct {
	upstream     string
	dialArgument dialArgument
}

func (c *DnsController) Handle_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		qname = dnsMessage.Question[0].Name
		qtype = dnsMessage.Question[0].Qtype
	}

	// Check ip version preference and qtype.
	switch qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			return c.handle_(dnsMessage, req, true)
		}
	default:
		return c.handle_(dnsMessage, req, true)
	}

	// Try to make both A and AAAA lookups.
	dnsMessage2 := deepcopy.Copy(dnsMessage).(*dnsmessage.Msg)
	dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
	var qtype2 uint16
	switch qtype {
	case dnsmessage.TypeA:
		qtype2 = dnsmessage.TypeAAAA
	case dnsmessage.TypeAAAA:
		qtype2 = dnsmessage.TypeA
	default:
		return fmt.Errorf("unexpected qtype path")
	}
	if len(dnsMessage2.Question) > 0 {
		dnsMessage2.Question[0].Qtype = qtype2
	}

	done := make(chan struct{})
	go func() {
		_ = c.handle_(dnsMessage2, req, false)
		done <- struct{}{}
	}()
	err = c.handle_(dnsMessage, req, false)
	<-done
	if err != nil {
		return err
	}

	// Join results and consider whether to response.
	resp := c.LookupDnsRespCache_(dnsMessage, c.cacheKey(qname, qtype), true)
	if resp == nil {
		// resp is not valid.
		c.log.WithFields(logrus.Fields{
			"qname": qname,
		}).Tracef("Reject %v due to resp not valid", qtype)
		return c.sendReject_(dnsMessage, req)
	}
	// resp is valid.
	cache2 := c.LookupDnsRespCache(c.cacheKey(qname, qtype2), true)
	if c.qtypePrefer == qtype || cache2 == nil || !cache2.IncludeAnyIp() {
		return sendPkt(c.log, resp, req.realDst, req.realSrc, req.src, req.lConn)
	} else {
		return c.sendReject_(dnsMessage, req)
	}
}

func (c *DnsController) handle_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
) (err error) {
	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
	}

	// Route request.
	upstreamIndex, upstream, err := c.routing.RequestSelect(qname, qtype)
	if err != nil {
		// 修复：如果路由选择失败，发送拒绝响应
		cacheKey := c.cacheKey(qname, qtype)
		c.RemoveDnsRespCache(cacheKey)
		return c.sendReject_(dnsMessage, req)
	}

	cacheKey := c.cacheKey(qname, qtype)

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		// Reject with empty answer.
		c.RemoveDnsRespCache(cacheKey)
		return c.sendReject_(dnsMessage, req)
	}

	// First, try to return cache immediately (fast path)
	if resp := c.LookupDnsRespCache_(dnsMessage, cacheKey, false); resp != nil {
		if needResp {
			if err = sendPkt(c.log, resp, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
				return fmt.Errorf("failed to write cached DNS resp: %w", err)
			}
		}
		return nil
	}

	// 简化处理：直接处理DNS请求，移除复杂的并发控制
	// 原来的并发控制逻辑过于复杂，可能导致性能问题

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := upstreamIndex.String()
		if upstream != nil {
			upstreamName = upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}

	// 修复：检查upstream是否有效
	if upstream == nil && upstreamIndex != consts.DnsRequestOutboundIndex_AsIs {
		c.log.Warnf("Invalid upstream for index %v", upstreamIndex)
		return c.sendReject_(dnsMessage, req)
	}

	// Re-pack DNS packet.
	data, err := dnsMessage.Pack()
	if err != nil {
		return err
	}
	return c.dialSend(0, req, data, dnsMessage.Id, upstream, needResp)
}

// sendReject_ send empty answer.
func (c *DnsController) sendReject_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeSuccess
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Reject")
	}
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
		return err
	}
	return nil
}

func (c *DnsController) dialSend(invokingDepth int, req *udpRequest, data []byte, id uint16, upstream *dns.Upstream, needResp bool) (err error) {
	if invokingDepth >= MaxDnsLookupDepth {
		return fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}

	upstreamName := "asis"
	if upstream == nil {
		// As-is.

		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		var ip46 netutils.Ip46
		if req.realDst.Addr().Is4() {
			ip46.Ip4 = req.realDst.Addr()
		} else {
			ip46.Ip6 = req.realDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.realDst.Addr().String(),
			Port:     req.realDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	// 修复：检查upstream是否有效
	if upstream == nil {
		return fmt.Errorf("invalid upstream configuration")
	}

	// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
	dialArgument, err := c.bestDialerChooser(req, upstream)
	if err != nil {
		return err
	}

	networkType := &dialer.NetworkType{
		L4Proto:   dialArgument.l4proto,
		IpVersion: dialArgument.ipversion,
		IsDns:     true,
	}

	// Dial and send.
	var respMsg *dnsmessage.Msg

	ctxDial, cancel := context.WithTimeout(context.TODO(), 3*time.Second) // DNS专用超时，比默认的8秒更短
	defer cancel()

	// Use the new forwarder manager to avoid duplicate creation.
	forwarder, releaseForwarder, err := c.forwarderManager.GetForwarder(upstream, *dialArgument)
	if err != nil {
		return err
	}
	defer releaseForwarder()

	respMsg, err = forwarder.ForwardDNS(ctxDial, data)
	if err != nil {
		// 如果DNS转发失败，发送拒绝响应而不是直接返回错误
		if needResp {
			// 创建一个拒绝响应
			rejectMsg := &dnsmessage.Msg{
				MsgHdr: dnsmessage.MsgHdr{
					Id:                 id,
					Response:           true,
					Rcode:              dnsmessage.RcodeServerFailure,
					RecursionAvailable: true,
				},
				Question: []dnsmessage.Question{}, // 空问题列表
			}
			rejectMsg.Compress = true
			rejectData, packErr := rejectMsg.Pack()
			if packErr != nil {
				return fmt.Errorf("failed to pack reject response: %w", packErr)
			}
			if sendErr := sendPkt(c.log, rejectData, req.realDst, req.realSrc, req.src, req.lConn); sendErr != nil {
				return fmt.Errorf("failed to send reject response: %w", sendErr)
			}
		}
		// 修复：不返回错误，而是记录日志并继续
		c.log.WithError(err).Warnf("DNS forward failed for upstream %v", upstreamName)
		return nil
	}

	// Route response.
	upstreamIndex, nextUpstream, err := c.routing.ResponseSelect(respMsg, upstream)
	if err != nil {
		return err
	}
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		// Accept.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		// Reject the request with empty answer.
		respMsg.Answer = nil
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
		// We also cache response reject.
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      respMsg.Question,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.dialSend(invokingDepth+1, req, data, id, nextUpstream, needResp)
	}
	if upstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.InfoLevel) {
		var (
			qname string
			qtype string
		)
		if len(respMsg.Question) > 0 {
			q := respMsg.Question[0]
			qname = strings.ToLower(q.Name)
			qtype = QtypeToString(q.Qtype)
		}
		fields := logrus.Fields{
			"network":  networkType.String(),
			"outbound": dialArgument.bestOutbound.Name,
			"policy":   dialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   dialArgument.bestDialer.Property().Name,
			"_qname":   qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch upstreamIndex {
		case consts.DnsResponseOutboundIndex_Accept:
			c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(dialArgument.bestTarget))
		case consts.DnsResponseOutboundIndex_Reject:
			c.log.WithFields(fields).Infof("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr()))
		default:
			return fmt.Errorf("unknown upstream: %v", upstreamIndex.String())
		}
	}
	if err = c.NormalizeAndCacheDnsResp_(respMsg); err != nil {
		return err
	}
	if needResp {
		// Keep the id the same with request.
		respMsg.Id = id
		respMsg.Compress = true
		data, err = respMsg.Pack()
		if err != nil {
			return err
		}
		if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
			return err
		}
	}
	return nil
}

// DnsForwarderManager provides DNS forwarder caching/creation for DNS controller (with cache and refcount)
type DnsForwarderManager struct {
	cache sync.Map // map[dnsForwarderKey]*forwarderEntry
}

type forwarderEntry struct {
	fwd DnsForwarder
	ref int32
	mu  sync.Mutex
}

func NewDnsForwarderManager() *DnsForwarderManager {
	return &DnsForwarderManager{}
}

func (m *DnsForwarderManager) GetForwarder(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, func(), error) {
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: dialArgument}
	var entry *forwarderEntry
	actual, loaded := m.cache.Load(key)
	if loaded {
		var ok bool
		entry, ok = actual.(*forwarderEntry)
		if !ok {
			m.cache.Delete(key)
			loaded = false
		}
	}
	if !loaded {
		fwd, err := newDnsForwarder(upstream, dialArgument)
		if err != nil {
			return nil, func() {}, err
		}
		entry = &forwarderEntry{fwd: fwd, ref: 1}
		m.cache.Store(key, entry)
	} else {
		entry.mu.Lock()
		entry.ref++
		entry.mu.Unlock()
	}
	release := func() {
		entry.mu.Lock()
		entry.ref--
		if entry.ref == 0 {
			entry.mu.Unlock()
			entry.fwd.Close()
			m.cache.Delete(key)
			return
		}
		entry.mu.Unlock()
	}
	return entry.fwd, release, nil
}

func (c *DnsController) optimizedCleanupExpiredCache() {
	// 使用更长的初始间隔，减少频繁清理
	cleanupInterval := 5 * time.Minute
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 检查是否需要清理
			if !c.shouldPerformCleanup() {
				continue
			}

			// 执行清理
			cleaned, cacheSize, expiredRatio := c.performOptimizedCleanup()

			// 更新统计信息
			c.updateCleanupStats(cleaned, cacheSize, expiredRatio)

			// 动态调整下次清理时间
			c.adjustNextCleanupTime(cleaned, cacheSize, expiredRatio)

		case <-c.stopCleanup:
			return
		}
	}
}

func (c *DnsController) shouldPerformCleanup() bool {
	c.cleanupStats.RLock()
	defer c.cleanupStats.RUnlock()

	// 如果距离上次清理时间太短，跳过
	if time.Since(c.cleanupStats.lastCleanupTime) < c.cleanupConfig.minInterval {
		return false
	}

	// 如果缓存很小，减少清理频率
	if c.cleanupStats.cacheSize < 50 {
		return time.Since(c.cleanupStats.lastCleanupTime) > 10*time.Minute
	}

	return true
}

func (c *DnsController) performOptimizedCleanup() (cleaned, cacheSize int, expiredRatio float64) {
	now := time.Now()
	cleaned = 0
	total := 0
	expired := 0
	batchCount := 0

	// 限制每次清理的数量，避免长时间阻塞
	maxCleanup := c.cleanupConfig.batchSize

	// 使用更高效的遍历方式
	c.dnsCache.Range(func(key, value any) bool {
		total++

		// 限制清理批次数
		if batchCount >= maxCleanup {
			return false // 停止遍历
		}

		cache, ok := value.(*DnsCache)
		if !ok {
			// 直接删除无效项
			c.dnsCache.Delete(key)
			cleaned++
			batchCount++
			return true
		}

		if !cache.Deadline.After(now) {
			// 缓存已过期，立即删除
			if c.cacheRemoveCallback != nil {
				_ = c.cacheRemoveCallback(cache)
			}
			c.dnsCache.Delete(key)
			cleaned++
			expired++
			batchCount++
		}

		return true
	})

	cacheSize = total - cleaned
	if total > 0 {
		expiredRatio = float64(expired) / float64(total)
	}

	if cleaned > 0 && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.Debugf("Optimized cleanup: cleaned %d/%d expired entries, remaining: %d", cleaned, batchCount, cacheSize)
	}

	return cleaned, cacheSize, expiredRatio
}

func (c *DnsController) updateCleanupStats(cleaned, cacheSize int, expiredRatio float64) {
	c.cleanupStats.Lock()
	defer c.cleanupStats.Unlock()

	// 使用更轻量的统计更新
	if c.cleanupStats.avgCleanupCount == 0 {
		c.cleanupStats.avgCleanupCount = float64(cleaned)
	} else {
		// 使用更小的平滑因子，减少计算开销
		alpha := 0.2
		c.cleanupStats.avgCleanupCount = alpha*float64(cleaned) + (1-alpha)*c.cleanupStats.avgCleanupCount
	}

	c.cleanupStats.lastCleanupCount = cleaned
	c.cleanupStats.lastCleanupTime = time.Now()
	c.cleanupStats.cacheSize = cacheSize
	c.cleanupStats.expiredRatio = expiredRatio
}

func (c *DnsController) adjustNextCleanupTime(cleaned, cacheSize int, expiredRatio float64) {
	c.cleanupStats.Lock()
	defer c.cleanupStats.Unlock()

	// 简化的间隔计算
	baseInterval := c.cleanupConfig.minInterval

	// 根据缓存大小和过期比例调整
	if cacheSize > 1000 || expiredRatio > 0.2 {
		// 缓存大或过期比例高，缩短间隔
		baseInterval = c.cleanupConfig.minInterval
	} else if cacheSize < 100 && expiredRatio < 0.05 {
		// 缓存小且过期比例低，延长间隔
		baseInterval = c.cleanupConfig.maxInterval
	} else {
		// 中等情况，使用中等间隔
		baseInterval = 10 * time.Minute
	}

	c.cleanupStats.nextCleanupTime = time.Now().Add(baseInterval)
}

// GetCleanupStats 返回DNS缓存清理统计信息
func (c *DnsController) GetCleanupStats() map[string]interface{} {
	c.cleanupStats.RLock()
	defer c.cleanupStats.RUnlock()

	return map[string]interface{}{
		"last_cleanup_time":  c.cleanupStats.lastCleanupTime,
		"next_cleanup_time":  c.cleanupStats.nextCleanupTime,
		"last_cleanup_count": c.cleanupStats.lastCleanupCount,
		"avg_cleanup_count":  c.cleanupStats.avgCleanupCount,
		"cache_size":         c.cleanupStats.cacheSize,
		"expired_ratio":      c.cleanupStats.expiredRatio,
		"cleanup_enabled":    c.cleanupConfig.enabled,
		"batch_size":         c.cleanupConfig.batchSize,
	}
}

// SetCleanupConfig 允许动态调整清理配置
func (c *DnsController) SetCleanupConfig(enabled bool, minInterval, maxInterval time.Duration, batchSize int) {
	c.cleanupConfig.Lock()
	defer c.cleanupConfig.Unlock()

	c.cleanupConfig.enabled = enabled
	if minInterval > 0 {
		c.cleanupConfig.minInterval = minInterval
	}
	if maxInterval > 0 {
		c.cleanupConfig.maxInterval = maxInterval
	}
	if batchSize > 0 {
		c.cleanupConfig.batchSize = batchSize
	}
}

func (c *DnsController) Close() {
	// 停止缓存清理协程
	close(c.stopCleanup)

	// 清理所有缓存
	c.dnsCache.Range(func(key, value any) bool {
		cache, ok := value.(*DnsCache)
		if ok && c.cacheRemoveCallback != nil {
			_ = c.cacheRemoveCallback(cache)
		}
		c.dnsCache.Delete(key)
		return true
	})

	// 修复：清理所有转发器
	if c.forwarderManager != nil {
		c.forwarderManager.cache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*forwarderEntry); ok {
				entry.mu.Lock()
				entry.fwd.Close()
				entry.mu.Unlock()
			}
			c.forwarderManager.cache.Delete(key)
			return true
		})
	}
}
