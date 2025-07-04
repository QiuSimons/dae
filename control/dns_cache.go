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

type LookupCache struct {
	DomainBitmap []uint32
	DnsCache
}

type DnsCache struct {
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

type DnsCacheEntry interface {
	SetAnswer([]dnsmessage.RR)
	SetDeadline(time.Time)
	GetDeadline() time.Time
	FillInto(req *dnsmessage.Msg)
}

func (c *DnsCache) SetAnswer(a []dnsmessage.RR) { c.Answer = a }
func (c *DnsCache) SetDeadline(t time.Time)     { c.Deadline = t }
func (c *DnsCache) GetDeadline() time.Time      { return c.Deadline }

var _ DnsCacheEntry = (*DnsCache)(nil)
var _ DnsCacheEntry = (*LookupCache)(nil)

const (
	DnsCacheMaxSize = 16384
)

type lruEntry struct {
	key   string
	value DnsCacheEntry
}

type commonDnsCache struct {
	cache         map[string]*list.Element
	lruList       *list.List
	mu            sync.Mutex
	newCacheEntry func(fqdn string, answers []dnsmessage.RR, deadline time.Time) (DnsCacheEntry, error)
}

func newCommonDnsCache(
	newCacheEntry func(fqdn string, answers []dnsmessage.RR, deadline time.Time) (DnsCacheEntry, error),
) *commonDnsCache {
	return &commonDnsCache{
		cache:         make(map[string]*list.Element),
		lruList:       list.New(),
		newCacheEntry: newCacheEntry,
	}
}

func (c *commonDnsCache) Get(cacheKey string) DnsCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.cache[cacheKey]; ok {
		cache := elem.Value.(*lruEntry).value
		c.lruList.MoveToFront(elem)
		return cache
	}
	return nil
}

func (c *commonDnsCache) Delete(cacheKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.cache[cacheKey]; ok {
		delete(c.cache, cacheKey)
		c.lruList.Remove(elem)
	}
}

// TODO: Delete callback
// gc must be called under write lock
func (c *commonDnsCache) gc() {
	for c.lruList.Len() > DnsCacheMaxSize {
		lruElement := c.lruList.Back()
		if lruElement == nil {
			return
		}
		entry := lruElement.Value.(*lruEntry)
		if entry.value.GetDeadline().Before(time.Now()) {
			delete(c.cache, entry.key)
			c.lruList.Remove(lruElement)
		} else {
			// Non-expired entries will not be evicted.
			// The LRU entry is not expired, so we stop the GC.
			break
		}
	}
}

func (c *commonDnsCache) UpdateDeadline(fqdn string, cacheKey string, answers []dnsmessage.RR, deadline time.Time) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.cache[cacheKey]; ok {
		entry := elem.Value.(*lruEntry)
		entry.value.SetAnswer(answers)
		entry.value.SetDeadline(deadline)
		c.lruList.MoveToFront(elem)
	} else {
		cache, err := c.newCacheEntry(fqdn, answers, deadline)
		if err != nil {
			return err
		}
		entry := &lruEntry{
			key:   cacheKey,
			value: cache,
		}
		elem := c.lruList.PushFront(entry)
		c.cache[cacheKey] = elem
		c.gc()
	}
	return nil
}

func (c *commonDnsCache) UpdateTtl(fqdn string, cacheKey string, answers []dnsmessage.RR, ttl int) (err error) {
	return c.UpdateDeadline(fqdn, cacheKey, answers, time.Now().Add(time.Duration(ttl)*time.Second))
}
