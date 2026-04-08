//go:build linux

package controlapi

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseConntrackLine(t *testing.T) {
	line := "ipv4     2 tcp      6 7439 ESTABLISHED src=10.0.0.157 dst=10.0.0.253 sport=59166 dport=9090 packets=117 bytes=6638 src=10.0.0.253 dst=10.0.0.157 sport=9090 dport=59166 packets=116 bytes=145159 [ASSURED] mark=0 zone=0 use=2"
	tuple, counter, ok := parseConntrackLine(line)
	if !ok {
		t.Fatal("parseConntrackLine() = false, want true")
	}

	if tuple.network != "tcp" {
		t.Fatalf("tuple.network = %q, want tcp", tuple.network)
	}
	if tuple.sourceAddress != netip.MustParseAddr("10.0.0.157") || tuple.destinationAddr != netip.MustParseAddr("10.0.0.253") {
		t.Fatalf("unexpected tuple addresses: %+v", tuple)
	}
	if tuple.sourcePort != 59166 || tuple.destinationPort != 9090 {
		t.Fatalf("unexpected tuple ports: %+v", tuple)
	}
	if counter.upload != 6638 || counter.download != 145159 {
		t.Fatalf("unexpected counters: %+v", counter)
	}
}

func TestBuildConntrackTelemetryLocked(t *testing.T) {
	tuple := conntrackTuple{
		network:         "tcp",
		sourceAddress:   netip.MustParseAddr("10.0.0.2"),
		sourcePort:      1000,
		destinationAddr: netip.MustParseAddr("1.1.1.1"),
		destinationPort: 443,
	}

	provider := &DaeProvider{}
	first := provider.buildConntrackTelemetryLocked(time.Unix(100, 0), map[conntrackTuple]conntrackCounter{
		tuple: {
			upload:   1000,
			download: 2000,
		},
	})

	if !first.available {
		t.Fatal("first telemetry unavailable")
	}
	if first.uploadRate != 0 || first.downloadRate != 0 {
		t.Fatalf("first rates = %+v, want zero", first)
	}
	if first.uploadTotal != 1000 || first.downloadTotal != 2000 {
		t.Fatalf("first totals = %+v, want upload=1000 download=2000", first)
	}

	second := provider.buildConntrackTelemetryLocked(time.Unix(105, 0), map[conntrackTuple]conntrackCounter{
		tuple: {
			upload:   1600,
			download: 2600,
		},
	})

	if second.uploadRate != 120 || second.downloadRate != 120 {
		t.Fatalf("second rates = %+v, want 120 B/s", second)
	}
	if second.uploadTotal != 1600 || second.downloadTotal != 2600 {
		t.Fatalf("second totals = %+v, want upload=1600 download=2600", second)
	}

	metric := second.metrics[tuple]
	if metric.uploadRate != 120 || metric.downloadRate != 120 {
		t.Fatalf("connection metric = %+v, want 120 B/s", metric)
	}
}
