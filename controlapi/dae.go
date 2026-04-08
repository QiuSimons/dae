//go:build linux

package controlapi

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

var (
	tcp4HealthType = dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}
	tcp6HealthType = dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_6,
	}
)

type DaeProvider struct {
	version         string
	configPath      string
	conf            *config.Config
	plane           *control.ControlPlane
	defaultPolicies map[string]outbound.DialerSelectionPolicy
	loggers         []*logrus.Logger
}

func NewDaeProvider(version string, conf *config.Config, plane *control.ControlPlane, configPath string, loggers ...*logrus.Logger) (*DaeProvider, error) {
	defaultPolicies := map[string]outbound.DialerSelectionPolicy{
		consts.OutboundDirect.String(): {
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		consts.OutboundBlock.String(): {
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
	}
	for _, group := range conf.Group {
		policy, err := outbound.NewDialerSelectionPolicyFromGroupParam(&group)
		if err != nil {
			return nil, fmt.Errorf("build external controller policy snapshot for group %q: %w", group.Name, err)
		}
		defaultPolicies[group.Name] = *policy
	}
	return &DaeProvider{
		version:         version,
		configPath:      configPath,
		conf:            conf,
		plane:           plane,
		defaultPolicies: defaultPolicies,
		loggers:         loggers,
	}, nil
}

func (p *DaeProvider) Hello() string {
	return "dae"
}

func (p *DaeProvider) Version() string {
	return p.version
}

func (p *DaeProvider) Meta() bool {
	return false
}

func (p *DaeProvider) Config() Config {
	return Config{
		Port:        0,
		SocksPort:   0,
		RedirPort:   0,
		TProxyPort:  int(p.conf.Global.TproxyPort),
		MixedPort:   0,
		AllowLan:    len(p.conf.Global.LanInterface) > 0,
		BindAddress: "0.0.0.0",
		Mode:        "rule",
		LogLevel:    p.conf.Global.LogLevel,
		IPv6:        true,
	}
}

func (p *DaeProvider) DaeConfigDocument() (DaeConfigDocument, error) {
	if p.configPath == "" {
		return DaeConfigDocument{}, fmt.Errorf("config file path is unavailable")
	}
	content, err := os.ReadFile(p.configPath)
	if err != nil {
		return DaeConfigDocument{}, fmt.Errorf("read config file: %w", err)
	}
	return DaeConfigDocument{
		Path:    p.configPath,
		Content: string(content),
	}, nil
}

func (p *DaeProvider) Memory() Memory {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return Memory{
		Inuse:   stats.Alloc,
		OSLimit: 0,
	}
}

func (p *DaeProvider) Traffic() Traffic {
	return Traffic{}
}

func (p *DaeProvider) Proxies() map[string]Proxy {
	proxies := make(map[string]Proxy)
	for _, group := range p.plane.Outbounds() {
		if group == nil {
			continue
		}
		if isBuiltinOutbound(group.Name) && len(group.Dialers) == 1 {
			leaf := p.buildLeafProxy(group.Dialers[0])
			leaf.Type = builtinProxyType(group.Name)
			proxies[leaf.Name] = leaf
			continue
		}

		proxies[group.Name] = p.buildGroupProxy(group)
		for _, d := range group.Dialers {
			if d == nil || d.Property() == nil {
				continue
			}
			if _, exists := proxies[d.Property().Name]; exists {
				continue
			}
			proxies[d.Property().Name] = p.buildLeafProxy(d)
		}
	}
	return proxies
}

func (p *DaeProvider) Proxy(name string) (Proxy, bool) {
	proxy, ok := p.Proxies()[name]
	return proxy, ok
}

func (p *DaeProvider) UpdateProxy(groupName, proxyName string) error {
	group := p.plane.OutboundByName(groupName)
	if group == nil {
		return providerErrNotFound
	}
	if isBuiltinOutbound(group.Name) {
		return fmt.Errorf("built-in outbound %q cannot be updated", group.Name)
	}
	index, _ := group.FindDialerByName(proxyName)
	if index < 0 {
		return fmt.Errorf("proxy %q not found in group %q", proxyName, groupName)
	}
	group.SetSelectionPolicy(outbound.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: index,
	})
	return nil
}

func (p *DaeProvider) ResetProxy(groupName string) error {
	group := p.plane.OutboundByName(groupName)
	if group == nil {
		return providerErrNotFound
	}
	policy, ok := p.defaultPolicies[groupName]
	if !ok {
		return fmt.Errorf("default policy for group %q is unavailable", groupName)
	}
	group.SetSelectionPolicy(policy)
	return nil
}

func (p *DaeProvider) Delay(name, probeURL string, timeout time.Duration) (int, error) {
	target, err := p.resolveProxyTarget(name)
	if err != nil {
		return 0, err
	}
	if target == nil {
		return 0, fmt.Errorf("proxy %q is unavailable", name)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if probeURL == "" {
		return p.defaultDelay(ctx, target)
	}
	return p.urlDelay(ctx, target, probeURL)
}

func (p *DaeProvider) SetLogLevel(level string) error {
	parsed, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	p.conf.Global.LogLevel = parsed.String()
	for _, logger := range p.loggers {
		if logger != nil {
			logger.SetLevel(parsed)
		}
	}
	return nil
}

func (p *DaeProvider) UpdateDaeConfig(content string) error {
	if p.configPath == "" {
		return fmt.Errorf("config file path is unavailable")
	}

	dir := filepath.Dir(p.configPath)
	tmp, err := os.CreateTemp(dir, ".dae-controller-*.dae")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	mode := os.FileMode(0600)
	if stat, err := os.Stat(p.configPath); err == nil {
		mode = stat.Mode().Perm()
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temp config mode: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}

	if err := validateDaeConfigFile(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, p.configPath); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		return fmt.Errorf("send reload signal: %w", err)
	}
	return nil
}

func validateDaeConfigFile(path string) error {
	merger := config.NewMerger(path)
	sections, _, err := merger.Merge()
	if err != nil {
		return err
	}
	if _, err := config.New(sections); err != nil {
		return err
	}
	return nil
}

func (p *DaeProvider) buildGroupProxy(group *outbound.DialerGroup) Proxy {
	all := make([]string, 0, len(group.Dialers))
	alive := false
	for _, d := range group.Dialers {
		if d == nil || d.Property() == nil {
			continue
		}
		all = append(all, d.Property().Name)
		if dialerAlive(d) {
			alive = true
		}
	}

	now := ""
	history := []DelayHistory{}
	if preferred := p.preferredDialer(group); preferred != nil && preferred.Property() != nil {
		now = preferred.Property().Name
		history = p.buildHistory(preferred)
	}

	return Proxy{
		Name:    group.Name,
		Type:    groupProxyType(p.defaultPolicyForGroup(group.Name)),
		Now:     now,
		All:     all,
		Alive:   alive,
		History: history,
		UDP:     true,
		XUDP:    false,
	}
}

func (p *DaeProvider) buildLeafProxy(d *dialer.Dialer) Proxy {
	prop := d.Property()
	return Proxy{
		Name:            prop.Name,
		Type:            protocolProxyType(prop.Protocol),
		Alive:           dialerAlive(d),
		History:         p.buildHistory(d),
		UDP:             true,
		XUDP:            false,
		Address:         prop.Address,
		Protocol:        prop.Protocol,
		SubscriptionTag: prop.SubscriptionTag,
	}
}

func (p *DaeProvider) buildHistory(d *dialer.Dialer) []DelayHistory {
	delay, ok := bestDelay(d)
	if !ok {
		return []DelayHistory{}
	}
	ms := delay.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	if ms > 65535 {
		ms = 65535
	}
	return []DelayHistory{{
		Time:  time.Now(),
		Delay: uint16(ms),
	}}
}

func (p *DaeProvider) resolveProxyTarget(name string) (*dialer.Dialer, error) {
	if group := p.plane.OutboundByName(name); group != nil {
		target := p.preferredDialer(group)
		if target == nil {
			return nil, fmt.Errorf("group %q has no available proxy", name)
		}
		return target, nil
	}

	for _, group := range p.plane.Outbounds() {
		if _, d := group.FindDialerByName(name); d != nil {
			return d, nil
		}
	}
	return nil, providerErrNotFound
}

func (p *DaeProvider) defaultDelay(ctx context.Context, d *dialer.Dialer) (int, error) {
	opt, err := d.TcpCheckOptionRaw.Option()
	if err != nil {
		return 0, err
	}
	ip, idx, err := pickProbeIP(opt.Ip46)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	ok, err := d.HttpCheck(ctx, idx, opt.Url, ip, opt.Method, d.SoMarkFromDae, d.Mptcp)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("probe failed")
	}
	return int(time.Since(start).Milliseconds()), nil
}

func (p *DaeProvider) urlDelay(ctx context.Context, d *dialer.Dialer, probeURL string) (int, error) {
	parsed, err := url.Parse(probeURL)
	if err != nil {
		return 0, err
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "http"
	}
	host := parsed.Hostname()
	if host == "" {
		return 0, fmt.Errorf("bad probe url")
	}

	var ip netip.Addr
	var idx int
	if parsedIP, parseErr := netip.ParseAddr(host); parseErr == nil {
		ip = parsedIP
		if ip.Is4() || ip.Is4In6() {
			idx = dialer.IdxTcp4
		} else {
			idx = dialer.IdxTcp6
		}
	} else {
		dnsServer, err := netip.ParseAddrPort(p.conf.Global.FallbackResolver)
		if err != nil {
			return 0, err
		}
		resolved, _, _ := netutils.ResolveIp46(
			ctx,
			d,
			dnsServer,
			host,
			common.MagicNetwork("udp", p.conf.Global.SoMarkFromDae, p.conf.Global.Mptcp),
			true,
		)
		ip, idx, err = pickProbeIP(resolved)
		if err != nil {
			return 0, err
		}
	}

	start := time.Now()
	ok, err := d.HttpCheck(ctx, idx, &netutils.URL{URL: parsed}, ip, p.conf.Global.TcpCheckHttpMethod, d.SoMarkFromDae, d.Mptcp)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("probe failed")
	}
	return int(time.Since(start).Milliseconds()), nil
}

func (p *DaeProvider) preferredDialer(group *outbound.DialerGroup) *dialer.Dialer {
	if group == nil {
		return nil
	}
	if fixed := group.CurrentFixedDialer(); fixed != nil {
		return fixed
	}

	policy := group.GetSelectionPolicy()
	var best *dialer.Dialer
	var bestScore time.Duration
	bestHasScore := false
	for _, candidate := range group.Dialers {
		if candidate == nil || candidate.Property() == nil {
			continue
		}
		score, ok := dialerScore(candidate, policy)
		if ok {
			if !bestHasScore || score < bestScore {
				best = candidate
				bestScore = score
				bestHasScore = true
			}
			continue
		}
		if best == nil && dialerAlive(candidate) {
			best = candidate
		}
	}
	if best != nil {
		return best
	}
	if len(group.Dialers) > 0 {
		return group.Dialers[0]
	}
	return nil
}

func (p *DaeProvider) defaultPolicyForGroup(name string) outbound.DialerSelectionPolicy {
	if policy, ok := p.defaultPolicies[name]; ok {
		return policy
	}
	return outbound.DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Fixed,
	}
}

func groupProxyType(policy outbound.DialerSelectionPolicy) string {
	switch policy.Policy {
	case consts.DialerSelectionPolicy_Random:
		return "LoadBalance"
	case consts.DialerSelectionPolicy_MinLastLatency,
		consts.DialerSelectionPolicy_MinAverage10Latencies,
		consts.DialerSelectionPolicy_MinMovingAverageLatencies:
		return "URLTest"
	case consts.DialerSelectionPolicy_Fixed:
		return "Selector"
	default:
		return "Selector"
	}
}

func protocolProxyType(protocol string) string {
	switch strings.ToLower(protocol) {
	case "ss":
		return "Shadowsocks"
	case "ssr":
		return "ShadowsocksR"
	case "socks5":
		return "Socks5"
	case "http", "https":
		return "Http"
	case "vmess":
		return "Vmess"
	case "vless":
		return "Vless"
	case "trojan":
		return "Trojan"
	case "hysteria":
		return "Hysteria"
	case "hysteria2":
		return "Hysteria2"
	case "tuic":
		return "Tuic"
	case "direct":
		return "Direct"
	case "block":
		return "Reject"
	default:
		return strings.Title(protocol)
	}
}

func builtinProxyType(name string) string {
	switch name {
	case consts.OutboundDirect.String():
		return "Direct"
	case consts.OutboundBlock.String():
		return "Reject"
	default:
		return "Selector"
	}
}

func isBuiltinOutbound(name string) bool {
	return name == consts.OutboundDirect.String() || name == consts.OutboundBlock.String()
}

func pickProbeIP(ip46 *netutils.Ip46) (netip.Addr, int, error) {
	if ip46 == nil {
		return netip.Addr{}, 0, errors.New("no probe ip available")
	}
	if ip46.Ip4.IsValid() {
		return ip46.Ip4, dialer.IdxTcp4, nil
	}
	if ip46.Ip6.IsValid() {
		return ip46.Ip6, dialer.IdxTcp6, nil
	}
	return netip.Addr{}, 0, errors.New("no probe ip available")
}

func dialerAlive(d *dialer.Dialer) bool {
	return d.SnapshotHealth(&tcp4HealthType).Alive || d.SnapshotHealth(&tcp6HealthType).Alive
}

func bestDelay(d *dialer.Dialer) (time.Duration, bool) {
	snapshots := []dialer.HealthSnapshot{
		d.SnapshotHealth(&tcp4HealthType),
		d.SnapshotHealth(&tcp6HealthType),
	}
	best := time.Duration(0)
	ok := false
	for _, snapshot := range snapshots {
		if !snapshot.LastLatencyOK {
			continue
		}
		if !ok || snapshot.LastLatency < best {
			best = snapshot.LastLatency
			ok = true
		}
	}
	return best, ok
}

func dialerScore(d *dialer.Dialer, policy consts.DialerSelectionPolicy) (time.Duration, bool) {
	snapshots := []dialer.HealthSnapshot{
		d.SnapshotHealth(&tcp4HealthType),
		d.SnapshotHealth(&tcp6HealthType),
	}
	values := make([]time.Duration, 0, len(snapshots))
	for _, snapshot := range snapshots {
		switch policy {
		case consts.DialerSelectionPolicy_MinAverage10Latencies:
			if snapshot.Average10LatencyOK {
				values = append(values, snapshot.Average10Latency)
			}
		case consts.DialerSelectionPolicy_MinMovingAverageLatencies:
			if snapshot.MovingAverageOK {
				values = append(values, snapshot.MovingAverage)
			}
		default:
			if snapshot.LastLatencyOK {
				values = append(values, snapshot.LastLatency)
			}
		}
	}
	if len(values) == 0 {
		return 0, false
	}
	slices.Sort(values)
	return values[0], true
}
