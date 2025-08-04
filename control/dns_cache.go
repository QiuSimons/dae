/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
)

type DnsCache struct {
	Fqdn     string
	Answer   []dnsmessage.RR
	Deadline time.Time
}

func (c *DnsCache) FillInto(req *dnsmessage.Msg) {
	req.Answer = deepcopy.Copy(c.Answer).([]dnsmessage.RR)
	req.Rcode = dnsmessage.RcodeSuccess
	req.Response = true
	req.RecursionAvailable = true
	req.Truncated = false
}

func (c *DnsCache) IncludeIp(ip netip.Addr) bool {
	for _, ans := range c.Answer {
		switch body := ans.(type) {
		case *dnsmessage.A:
			if !ip.Is4() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.A); ok && a == ip {
				return true
			}
		case *dnsmessage.AAAA:
			if !ip.Is6() {
				continue
			}
			if a, ok := netip.AddrFromSlice(body.AAAA); ok && a == ip {
				return true
			}
		}
	}
	return false
}

func (c *DnsCache) IncludeAnyIp() bool {
	for _, ans := range c.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}

type lruEntry[K comparable] struct {
	key   K
	value *DnsCache
}

type commonDnsCache[K comparable] struct {
	cache   map[K]*list.Element
	lruList *list.List
	mu      sync.Mutex
	maxSize int
}

func newCommonDnsCache[K comparable](maxSize int) *commonDnsCache[K] {
	return &commonDnsCache[K]{
		cache:   make(map[K]*list.Element),
		lruList: list.New(),
		maxSize: maxSize,
	}
}

func (c *commonDnsCache[K]) Get(cacheKey K) *DnsCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.cache[cacheKey]; ok {
		cache := elem.Value.(*lruEntry[K]).value
		c.lruList.MoveToFront(elem)
		return cache
	}
	return nil
}

func (c *commonDnsCache[K]) Delete(cacheKey K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.cache[cacheKey]; ok {
		delete(c.cache, cacheKey)
		c.lruList.Remove(elem)
	}
}

// TODO: Delete callback
// gc must be called under write lock
func (c *commonDnsCache[K]) gc() {
	for c.lruList.Len() > c.maxSize {
		lruElement := c.lruList.Back()
		if lruElement == nil {
			return
		}
		entry := lruElement.Value.(*lruEntry[K])
		if entry.value.Deadline.Before(time.Now()) {
			delete(c.cache, entry.key)
			c.lruList.Remove(lruElement)
		} else {
			// Non-expired entries will not be evicted.
			// The LRU entry is not expired, so we stop the GC.
			break
		}
	}
}

func (c *commonDnsCache[K]) UpdateDeadline(key K, fqdn string, answer []dnsmessage.RR, deadline time.Time) (bool, *DnsCache) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[key]; ok {
		entry := elem.Value.(*lruEntry[K])
		entry.value.Answer = answer
		entry.value.Deadline = deadline
		c.lruList.MoveToFront(elem)
		return false, entry.value
	} else {
		cache := &DnsCache{
			Fqdn:     fqdn,
			Answer:   answer,
			Deadline: deadline,
		}
		entry := &lruEntry[K]{
			key:   key,
			value: cache,
		}
		elem := c.lruList.PushFront(entry)
		c.cache[key] = elem
		c.gc()
		return true, cache
	}
}

func (c *commonDnsCache[K]) UpdateTtl(key K, fqdn string, answer []dnsmessage.RR, ttl int) (bool, *DnsCache) {
	return c.UpdateDeadline(key, fqdn, answer, time.Now().Add(time.Duration(ttl)*time.Second))
}
