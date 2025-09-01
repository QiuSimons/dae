package control

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	TotalConnections                                              prometheus.Counter
	ActiveConnections, ActiveConnectionsTCP, ActiveConnectionsUDP prometheus.Gauge
	DialLatency                                                   prometheus.Histogram
)

func init() {
	// Initialize with no-op implementations to prevent nil pointer dereferences
	// These will be replaced with real implementations when initPrometheus is called
	TotalConnections = prometheus.NewCounter(prometheus.CounterOpts{Name: "dae_noop_total_connections"})
	ActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{Name: "dae_noop_active_connections"})
	ActiveConnectionsTCP = prometheus.NewGauge(prometheus.GaugeOpts{Name: "dae_noop_active_connections_tcp"})
	ActiveConnectionsUDP = prometheus.NewGauge(prometheus.GaugeOpts{Name: "dae_noop_active_connections_udp"})
	DialLatency = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "dae_noop_dial_latency_seconds"})
}

func initPrometheus(registry *prometheus.Registry) {
	// Capture registry in a local variable to prevent nil pointer due to concurrent modification
	r := registry
	if r == nil {
		return
	}

	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_active_connections",
			Help: "Number of active connections",
		},
	)
	ActiveConnectionsTCP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_active_connections_tcp",
			Help: "Number of active TCP connections",
		},
	)
	ActiveConnectionsUDP = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_active_connections_udp",
			Help: "Number of active UDP connections",
		},
	)
	TotalConnections = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dae_total_connections",
			Help: "Total number of connections handled",
		},
	)
	DialLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dae_dial_latency_seconds",
			Help:    "Dial latency in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms ~ ~16s
		},
	)

	// Double-check registry is not nil before registering metrics
	if r == nil {
		return
	}
	r.MustRegister(ActiveConnections)
	r.MustRegister(ActiveConnectionsTCP)
	r.MustRegister(ActiveConnectionsUDP)
	r.MustRegister(TotalConnections)
	r.MustRegister(DialLatency)
}
