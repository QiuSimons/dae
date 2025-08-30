/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/dlclark/regexp2"
	log "github.com/sirupsen/logrus"
)

const (
	FilterInput_Name            = "name"
	FilterInput_SubscriptionTag = "subtag"
	FilterInput_Link            = "link"
)

const (
	FilterKey_Name_Regex   = "regex"
	FilterKey_Name_Keyword = "keyword"

	FilterInput_SubscriptionTag_Regex = "regex"
)

// NodeInfo stores the original node information for lazy creation
type NodeInfo struct {
	Link            string
	SubscriptionTag string
	Property        *dialer.Property
	Dialers         []D.Dialer
	CreatedDialer   *dialer.Dialer
}

func (n *NodeInfo) createDialer(option *dialer.GlobalOption, d netproxy.Dialer) (*dialer.Dialer, error) {
	for _, dialer := range n.Dialers {
		var err error
		d, err = dialer.Dialer(&option.ExtraOption, d)
		if err != nil {
			return nil, err
		}
	}
	return dialer.NewDialer(d, option, dialer.InstanceOption{DisableCheck: false}, n.Property), nil
}

func (n *NodeInfo) createDialerIfNeeded(option *dialer.GlobalOption) (*dialer.Dialer, error) {
	if n.CreatedDialer == nil {
		d, err := n.createDialer(option, direct.Direct)
		if err != nil {
			return nil, err
		}
		n.CreatedDialer = d
	}
	return n.CreatedDialer, nil
}

type DialerSet struct {
	option       *dialer.GlobalOption
	nodeInfos    []*NodeInfo
	nodeToTagMap map[*dialer.Dialer]string // Only for created dialers
}

func NewDialerSetFromLinks(option *dialer.GlobalOption, tagToNodeList map[string][]string) *DialerSet {
	s := &DialerSet{
		option:       option,
		nodeInfos:    make([]*NodeInfo, 0),
		nodeToTagMap: make(map[*dialer.Dialer]string),
	}
	for subscriptionTag, nodes := range tagToNodeList {
		for _, node := range nodes {
			d, p, err := D.NewFromLink(node)
			if err != nil {
				log.Warnf("failed to parse node %v: %v", node, err)
				continue
			}
			nodeInfo := &NodeInfo{
				Link:            node,
				SubscriptionTag: subscriptionTag,
				Property: &dialer.Property{
					Property:        *p,
					SubscriptionTag: subscriptionTag,
				},
				Dialers: d,
			}
			s.nodeInfos = append(s.nodeInfos, nodeInfo)
		}
	}
	return s
}

func (s *DialerSet) filterHit(nodeInfo *NodeInfo, filters []*config_parser.Function) (hit bool, err error) {
	if len(filters) == 0 {
		// No filter.
		return true, nil
	}

	// Example
	// filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')
	// filter: !name(regex: 'HK|TW|SG') && name(keyword: disney)
	// filter: subtag(my_sub, regex:^my_, regex:my_)

	// And
	for _, filter := range filters {
		var subFilterHit bool

		switch filter.Name {
		case FilterInput_Name:
			// Or
		loop:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterKey_Name_Regex:
					regex, err := regexp2.Compile(param.Val, 0)
					if err != nil {
						return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
					}
					matched, _ := regex.MatchString(nodeInfo.Property.Name)
					//logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break loop
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(nodeInfo.Property.Name, param.Val) {
						subFilterHit = true
						break loop
					}
				case "":
					if nodeInfo.Property.Name == param.Val {
						subFilterHit = true
						break loop
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}
		case FilterInput_SubscriptionTag:
			// Or
		loop2:
			for _, param := range filter.Params {
				switch param.Key {
				case FilterInput_SubscriptionTag_Regex:
					regex, err := regexp2.Compile(param.Val, 0)
					if err != nil {
						return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
					}
					matched, _ := regex.MatchString(nodeInfo.SubscriptionTag)
					if matched {
						subFilterHit = true
						break loop2
					}
					//logrus.Warnln(param.Val, matched, dialer.Name())
				case "":
					// Full
					if nodeInfo.SubscriptionTag == param.Val {
						subFilterHit = true
						break loop2
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}

		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.Name)
		}

		if subFilterHit == filter.Not {
			return false, nil
		}
	}
	return true, nil
}

func (s *DialerSet) FilterAndAnnotate(filters [][]*config_parser.Function, annotations [][]*config_parser.Param, nextHop string) (dialers []*dialer.Dialer, filterAnnotations []*dialer.Annotation, err error) {
	if len(filters) != len(annotations) {
		return nil, nil, fmt.Errorf("[CODE BUG]: unmatched annotations length: %v filters and %v annotations", len(filters), len(annotations))
	}

	// Find NextHop dialer if specified
	nextHopInfo, err := s.findNextHop(nextHop)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find next_hop '%s': %w", nextHop, err)
	}

	if nextHop != "" {
		fmt.Printf("nextHop: %+v\n", nextHopInfo.Property)
	}

nextDialerLoop:
	for _, nodeInfo := range s.nodeInfos {
		if len(filters) == 0 {
			// No filters, create all dialers
			d, err := nodeInfo.createDialerIfNeeded(s.option)
			if err != nil {
				log.Infof("failed to create dialer for node %v: %v", nodeInfo.Link, err)
				continue
			}
			if nextHopInfo != nil {
				d, err = nextHopInfo.createDialer(s.option, d)
				if err != nil {
					log.Infof("failed to create dialer for node %v: %v", nodeInfo.Link, err)
					continue
				}
				d.Property.Name = fmt.Sprintf("%s->%s", d.Property.Name, nextHopInfo.Property.Name)
				d.Property.Protocol = fmt.Sprintf("%s->%s", d.Property.Protocol, nextHopInfo.Property.Protocol)
				d.Property.Address = fmt.Sprintf("%s->%s", d.Property.Address, nextHopInfo.Property.Address)
			}
			dialers = append(dialers, d)
			filterAnnotations = append(filterAnnotations, &dialer.Annotation{})
			continue
		}
		// Hit any.
		for j, filter := range filters {
			hit, err := s.filterHit(nodeInfo, filter)
			if err != nil {
				return nil, nil, err
			}
			if hit {
				// Create dialer if it hasn't been created yet
				d, err := nodeInfo.createDialerIfNeeded(s.option)
				if err != nil {
					log.Infof("failed to create dialer for node %v: %v", nodeInfo.Link, err)
					continue nextDialerLoop
				}
				if nextHopInfo != nil {
					d, err = nextHopInfo.createDialer(s.option, d)
					if err != nil {
						log.Infof("failed to create dialer for node %v: %v", nodeInfo.Link, err)
						continue nextDialerLoop
					}
					d.Property.Name = fmt.Sprintf("%s->%s", d.Property.Name, nextHopInfo.Property.Name)
					d.Property.Protocol = fmt.Sprintf("%s->%s", d.Property.Protocol, nextHopInfo.Property.Protocol)
					d.Property.Address = fmt.Sprintf("%s->%s", d.Property.Address, nextHopInfo.Property.Address)
				}

				anno, err := dialer.NewAnnotation(annotations[j])
				if err != nil {
					return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
				}
				dialers = append(dialers, d)
				filterAnnotations = append(filterAnnotations, anno)
				continue nextDialerLoop
			}
		}
	}
	return dialers, filterAnnotations, nil
}

func (s *DialerSet) findNextHop(nextHop string) (*NodeInfo, error) {
	if nextHop == "" {
		return nil, nil
	}
	// Search for the next hop node by name
	for _, nodeInfo := range s.nodeInfos {
		if nodeInfo.Property.Name == nextHop {
			return nodeInfo, nil
		}
	}
	return nil, fmt.Errorf("next_hop node '%s' not found", nextHop)
}

func (s *DialerSet) Close() error {
	var err error
	for _, nodeInfo := range s.nodeInfos {
		if nodeInfo.CreatedDialer != nil {
			if e := nodeInfo.CreatedDialer.Close(); e != nil {
				err = e
			}
		}
	}
	return err
}
