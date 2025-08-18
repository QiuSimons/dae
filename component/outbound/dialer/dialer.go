/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type DialerGroup interface {
	NotifyStatusChange(*Dialer)
}

type Dialer struct {
	*GlobalOption
	netproxy.Dialer
	*Property

	needAliveState bool
	alive          bool
	supported      [4]bool
	Latencies10    *LatenciesN
	MovingAverage  time.Duration

	mu                     sync.Mutex
	registeredDialerGroups map[DialerGroup]int

	tickerMu sync.Mutex
	ticker   *time.Ticker
	checkCh  chan time.Time
	ctx      context.Context
	cancel   context.CancelFunc

	checkActivated bool

	DialerPrometheus
}

type DialerPrometheus struct {
	prometheusRegistry                                            prometheus.Registerer
	TotalConnections                                              prometheus.Counter
	ActiveConnections, ActiveConnectionsTCP, ActiveConnectionsUDP prometheus.Gauge
	DialLatency                                                   prometheus.Histogram
}

func (d *DialerPrometheus) initPrometheus(registry prometheus.Registerer, name string) {
	d.ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("dae_active_connections_%s", name),
			Help: fmt.Sprintf("Number of active connections in %s", name),
		},
	)
	d.ActiveConnectionsTCP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("dae_active_connections_%s_tcp", name),
			Help: fmt.Sprintf("Number of active TCP connections in %s", name),
		},
	)
	d.ActiveConnectionsUDP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("dae_active_connections_%s_udp", name),
			Help: fmt.Sprintf("Number of active UDP connections in %s", name),
		},
	)
	d.TotalConnections = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("dae_total_connections_%s", name),
			Help: fmt.Sprintf("Total number of connections handled in %s", name),
		},
	)
	d.DialLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    fmt.Sprintf("dae_dial_latency_seconds_%s", name),
			Help:    fmt.Sprintf("Dial latency in seconds in %s", name),
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms ~ ~16s
		},
	)
	registry.MustRegister(d.TotalConnections)
	registry.MustRegister(d.ActiveConnections)
	registry.MustRegister(d.ActiveConnectionsTCP)
	registry.MustRegister(d.ActiveConnectionsUDP)
	registry.MustRegister(d.DialLatency)
}

type GlobalOption struct {
	D.ExtraOption
	// TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
}

type Property struct {
	D.Property
	SubscriptionTag string
}

func NewGlobalOption(global *config.Global) *GlobalOption {
	return &GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:       global.AllowInsecure,
			TlsImplementation:   global.TlsImplementation,
			UtlsImitate:         global.UtlsImitate,
			BandwidthMaxTx:      global.BandwidthMaxTx,
			BandwidthMaxRx:      global.BandwidthMaxRx,
			TlsFragment:         global.TlsFragment,
			TlsFragmentLength:   global.TlsFragmentLength,
			TlsFragmentInterval: global.TlsFragmentInterval,
			UDPHopInterval:      global.UDPHopInterval,
		},
		// TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, property *Property, needAliveState bool, prometheusRegistry prometheus.Registerer) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:           option,
		Dialer:                 dialer,
		Property:               property,
		needAliveState:         needAliveState,
		alive:                  !needAliveState,
		Latencies10:            NewLatenciesN(10),
		registeredDialerGroups: make(map[DialerGroup]int),
		tickerMu:               sync.Mutex{},
		ticker:                 nil,
		checkCh:                make(chan time.Time, 1),
		ctx:                    ctx,
		cancel:                 cancel,
		DialerPrometheus:       DialerPrometheus{prometheusRegistry: prometheusRegistry},
	}
	d.initPrometheus(prometheusRegistry, d.Name)
	log.WithField("dialer", d.Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

func (d *Dialer) NeedAliveState() bool {
	return d.needAliveState
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.Property, d.needAliveState, d.prometheusRegistry)
}

func (d *Dialer) Close() error {
	d.cancel()
	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
	}
	d.tickerMu.Unlock()
	return nil
}
