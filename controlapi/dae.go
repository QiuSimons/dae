//go:build linux

package controlapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
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
	mu              sync.RWMutex
	probeHistory    map[string]DelayHistory
	trafficLastAt   time.Time
	trafficLastUp   uint64
	trafficLastDown uint64
	conntrackLastAt time.Time
	conntrackLast   map[conntrackTuple]conntrackCounter
	conntrackUp     uint64
	conntrackDown   uint64
	conntrackCache  conntrackSnapshot
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
		probeHistory:    map[string]DelayHistory{},
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

	merger := config.NewMerger(p.configPath)
	_, entries, err := merger.Merge()
	if err != nil {
		// Fallback to simple read if merge fails (e.g. syntax error or missing files)
		content, err := os.ReadFile(p.configPath)
		if err != nil {
			return DaeConfigDocument{}, err
		}
		return DaeConfigDocument{
			Path:    p.configPath,
			Content: string(content),
		}, nil
	}

	// Sort entries deterministically to prevent UI jumping.
	// Ensure the root configPath is always the first item.
	var sortedEntries []string
	var rootEntry string
	for _, entry := range entries {
		if filepath.Clean(entry) == filepath.Clean(p.configPath) {
			rootEntry = entry
		} else {
			sortedEntries = append(sortedEntries, entry)
		}
	}
	sort.Strings(sortedEntries)
	if rootEntry != "" {
		sortedEntries = append([]string{rootEntry}, sortedEntries...)
	} else {
		// Safety fallback if for some reason p.configPath isn't exactly matched
		sort.Strings(entries)
		sortedEntries = entries
	}

	dir := filepath.Dir(p.configPath)
	var sb strings.Builder
	for i, entry := range sortedEntries {
		content, err := os.ReadFile(entry)
		if err != nil {
			return DaeConfigDocument{}, fmt.Errorf("read entry %v: %w", entry, err)
		}

		rel, err := filepath.Rel(dir, entry)
		if err != nil {
			rel = entry
		}

		if i > 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "# --- FILE: %s ---\n", rel)
		sb.Write(content)
		sb.WriteString("\n")
	}

	return DaeConfigDocument{
		Path:    p.configPath,
		Content: sb.String(),
	}, nil
}

func (p *DaeProvider) Memory() Memory {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return Memory{
		Inuse:   stats.Alloc,
		RSS:     readProcessRSS(),
		OSLimit: 0,
	}
}

func readProcessRSS() uint64 {
	statm, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(statm))
	if len(fields) < 2 {
		return 0
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return residentPages * uint64(os.Getpagesize())
}

func clampUint64ToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

func (p *DaeProvider) conntrackTelemetrySnapshot(now time.Time) conntrackSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conntrackCache.available && !p.conntrackCache.updatedAt.IsZero() && now.Sub(p.conntrackCache.updatedAt) < conntrackCacheInterval {
		return p.conntrackCache
	}

	counters, err := readConntrackCounters()
	if err != nil {
		if p.conntrackCache.available {
			return p.conntrackCache
		}
		return conntrackSnapshot{}
	}

	telemetry := p.buildConntrackTelemetryLocked(now, counters)
	p.conntrackCache = telemetry
	return telemetry
}

func (p *DaeProvider) buildConntrackTelemetryLocked(now time.Time, counters map[conntrackTuple]conntrackCounter) conntrackSnapshot {
	telemetry := conntrackSnapshot{
		updatedAt: now,
		available: true,
		metrics:   make(map[conntrackTuple]conntrackMetric, len(counters)),
	}

	var (
		currentUpSum   uint64
		currentDownSum uint64
		deltaUpSum     uint64
		deltaDownSum   uint64
	)

	firstSample := p.conntrackLastAt.IsZero()
	elapsed := now.Sub(p.conntrackLastAt)

	for tuple, counter := range counters {
		currentUpSum += counter.upload
		currentDownSum += counter.download

		var deltaUpload uint64
		var deltaDownload uint64
		if !firstSample {
			previous, seen := p.conntrackLast[tuple]
			if seen {
				deltaUpload = diffConntrackCounter(counter.upload, previous.upload)
				deltaDownload = diffConntrackCounter(counter.download, previous.download)
			} else {
				deltaUpload = counter.upload
				deltaDownload = counter.download
			}
			deltaUpSum += deltaUpload
			deltaDownSum += deltaDownload
		}

		telemetry.metrics[tuple] = conntrackMetric{
			uploadTotal:   counter.upload,
			downloadTotal: counter.download,
			uploadRate:    conntrackRate(deltaUpload, elapsed),
			downloadRate:  conntrackRate(deltaDownload, elapsed),
		}
	}

	if firstSample {
		p.conntrackUp = currentUpSum
		p.conntrackDown = currentDownSum
	} else {
		p.conntrackUp += deltaUpSum
		p.conntrackDown += deltaDownSum
	}

	p.conntrackLastAt = now
	p.conntrackLast = counters

	telemetry.uploadTotal = p.conntrackUp
	telemetry.downloadTotal = p.conntrackDown
	telemetry.uploadRate = conntrackRate(deltaUpSum, elapsed)
	telemetry.downloadRate = conntrackRate(deltaDownSum, elapsed)
	return telemetry
}

func (p *DaeProvider) Traffic() Traffic {
	if p == nil {
		return Traffic{}
	}

	if telemetry := p.conntrackTelemetrySnapshot(time.Now()); telemetry.available {
		return Traffic{
			Up:        clampUint64ToInt64(telemetry.uploadRate),
			Down:      clampUint64ToInt64(telemetry.downloadRate),
			UpTotal:   clampUint64ToInt64(telemetry.uploadTotal),
			DownTotal: clampUint64ToInt64(telemetry.downloadTotal),
		}
	}

	if p.plane == nil {
		return Traffic{}
	}

	snapshot := p.plane.TrafficSnapshot()
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	var upRate int64
	var downRate int64
	if !p.trafficLastAt.IsZero() {
		if elapsed := now.Sub(p.trafficLastAt); elapsed > 0 {
			var upDelta uint64
			var downDelta uint64
			if snapshot.UpTotal >= p.trafficLastUp {
				upDelta = snapshot.UpTotal - p.trafficLastUp
			}
			if snapshot.DownTotal >= p.trafficLastDown {
				downDelta = snapshot.DownTotal - p.trafficLastDown
			}
			upRate = int64(float64(upDelta) / elapsed.Seconds())
			downRate = int64(float64(downDelta) / elapsed.Seconds())
		}
	}

	p.trafficLastAt = now
	p.trafficLastUp = snapshot.UpTotal
	p.trafficLastDown = snapshot.DownTotal

	return Traffic{
		Up:        upRate,
		Down:      downRate,
		UpTotal:   int64(snapshot.UpTotal),
		DownTotal: int64(snapshot.DownTotal),
	}
}

func (p *DaeProvider) Connections(limit int) ConnectionsSnapshot {
	snapshot := p.plane.LiveConnections(limit)
	telemetry := p.conntrackTelemetrySnapshot(time.Now())
	connections := make([]Connection, 0, len(snapshot.Connections))
	for _, conn := range snapshot.Connections {
		metrics := telemetry.metricsFor(conn.Network, conn.SourceAddress, conn.SourcePort, conn.DestinationAddress, conn.DestinationPort)
		connections = append(connections, Connection{
			ID:                 conn.ID,
			Network:            conn.Network,
			State:              conn.State,
			Source:             conn.Source,
			SourceAddress:      conn.SourceAddress,
			SourcePort:         conn.SourcePort,
			Destination:        conn.Destination,
			DestinationAddress: conn.DestinationAddress,
			DestinationPort:    conn.DestinationPort,
			Process:            conn.Process,
			PID:                conn.PID,
			Outbound:           conn.Outbound,
			Direction:          conn.Direction,
			Mark:               conn.Mark,
			DSCP:               conn.DSCP,
			Must:               conn.Must,
			HasRouting:         conn.HasRouting,
			Mac:                conn.Mac,
			LastSeen:           conn.LastSeen,
			UploadSpeed:        clampUint64ToInt64(metrics.uploadRate),
			DownloadSpeed:      clampUint64ToInt64(metrics.downloadRate),
			UploadTotal:        clampUint64ToInt64(metrics.uploadTotal),
			DownloadTotal:      clampUint64ToInt64(metrics.downloadTotal),
		})
	}
	return ConnectionsSnapshot{
		UpdatedAt:   snapshot.UpdatedAt,
		Total:       snapshot.Total,
		TCP:         snapshot.TCP,
		UDP:         snapshot.UDP,
		Connections: connections,
	}
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
		return errProviderNotFound
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
		return errProviderNotFound
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

	var delay int
	if probeURL == "" {
		delay, err = p.defaultDelay(ctx, target)
	} else {
		delay, err = p.urlDelay(ctx, target, probeURL)
	}
	if err != nil {
		return 0, err
	}

	p.recordProbeDelay(name, delay)
	if target.Property() != nil {
		p.recordProbeDelay(target.Property().Name, delay)
	}
	return delay, nil
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

	const markerPrefix = "# --- FILE: "
	const markerSuffix = " ---"

	if !strings.Contains(content, markerPrefix) {
		return p.updateSingleDaeConfig(p.configPath, content, true)
	}

	// Split by markers
	files := make(map[string]*strings.Builder)
	lines := strings.Split(content, "\n")
	currentFile := filepath.Base(p.configPath)
	var currentContent strings.Builder

	flushCurrent := func() {
		if currentFile != "" && currentContent.Len() > 0 {
			if _, exists := files[currentFile]; !exists {
				files[currentFile] = &strings.Builder{}
			} else {
				files[currentFile].WriteString("\n")
			}
			files[currentFile].WriteString(strings.TrimSpace(currentContent.String()))
			currentContent.Reset()
		}
	}

	for _, line := range lines {
		if strings.HasPrefix(line, markerPrefix) && strings.HasSuffix(line, markerSuffix) {
			flushCurrent()
			currentFile = strings.TrimPrefix(line, markerPrefix)
			currentFile = strings.TrimSuffix(currentFile, markerSuffix)
		} else if currentFile != "" {
			currentContent.WriteString(line)
			currentContent.WriteString("\n")
		}
	}
	flushCurrent()

	dir := filepath.Dir(p.configPath)
	for relPath, builder := range files {
		absPath := filepath.Join(dir, relPath)
		fileContent := builder.String()
		// Safety check: ensure the path is within the config directory
		if !strings.HasPrefix(filepath.Clean(absPath), filepath.Clean(dir)) {
			return fmt.Errorf("illegal file path: %s", relPath)
		}

		// Only send reload signal for the last file update
		if err := p.updateSingleDaeConfig(absPath, fileContent, false); err != nil {
			return err
		}
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		return fmt.Errorf("send reload signal: %w", err)
	}
	return nil
}

func (p *DaeProvider) updateSingleDaeConfig(path string, content string, reload bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".dae-controller-*.dae")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	mode := os.FileMode(0600)
	if stat, err := os.Stat(path); err == nil {
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

	// We only validate the entry file if it's a single file update or if we're updating the entry file itself.
	// But actually, validateDaeConfigFile might fail if sub-files are not yet updated.
	// This is a trade-off. For now, we only validate the file being written.
	if err := validateDaeConfigFile(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	if reload {
		if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
			return fmt.Errorf("send reload signal: %w", err)
		}
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
		history = p.historyForName(group.Name, preferred)
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
		History:         p.historyForName(prop.Name, d),
		UDP:             true,
		XUDP:            false,
		Address:         prop.Address,
		Protocol:        prop.Protocol,
		SubscriptionTag: prop.SubscriptionTag,
	}
}

func (p *DaeProvider) historyForName(name string, d *dialer.Dialer) []DelayHistory {
	if cached, ok := p.cachedProbeDelay(name); ok {
		return []DelayHistory{cached}
	}
	return p.buildHistory(d)
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

func (p *DaeProvider) cachedProbeDelay(name string) (DelayHistory, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	history, ok := p.probeHistory[name]
	return history, ok
}

func (p *DaeProvider) recordProbeDelay(name string, delay int) {
	if name == "" {
		return
	}
	if delay < 0 {
		delay = 0
	}
	if delay > 65535 {
		delay = 65535
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeHistory[name] = DelayHistory{
		Time:  time.Now(),
		Delay: uint16(delay),
	}
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
	return nil, errProviderNotFound
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
		return cases.Title(language.Und).String(protocol)
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
