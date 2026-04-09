//go:build linux

package controlapi

import (
	"bufio"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const conntrackCacheInterval = 900 * time.Millisecond

var conntrackProcPaths = []string{
	"/proc/net/nf_conntrack",
	"/proc/net/ip_conntrack",
}

type conntrackTuple struct {
	network         string
	sourceAddress   netip.Addr
	sourcePort      uint16
	destinationAddr netip.Addr
	destinationPort uint16
}

type conntrackCounter struct {
	upload   uint64
	download uint64
}

type conntrackMetric struct {
	uploadTotal   uint64
	downloadTotal uint64
	uploadRate    uint64
	downloadRate  uint64
}

type conntrackSnapshot struct {
	updatedAt     time.Time
	available     bool
	uploadTotal   uint64
	downloadTotal uint64
	uploadRate    uint64
	downloadRate  uint64
	metrics       map[conntrackTuple]conntrackMetric
}

func (s conntrackSnapshot) metricsFor(network, sourceAddress string, sourcePort uint16, destinationAddress string, destinationPort uint16) conntrackMetric {
	if !s.available {
		return conntrackMetric{}
	}

	src, err := netip.ParseAddr(sourceAddress)
	if err != nil {
		return conntrackMetric{}
	}
	dst, err := netip.ParseAddr(destinationAddress)
	if err != nil {
		return conntrackMetric{}
	}

	tuple := conntrackTuple{
		network:         strings.ToLower(network),
		sourceAddress:   src,
		sourcePort:      sourcePort,
		destinationAddr: dst,
		destinationPort: destinationPort,
	}
	if metric, ok := s.metrics[tuple]; ok {
		return metric
	}

	reverse := conntrackTuple{
		network:         tuple.network,
		sourceAddress:   dst,
		sourcePort:      destinationPort,
		destinationAddr: src,
		destinationPort: sourcePort,
	}
	metric, ok := s.metrics[reverse]
	if !ok {
		return conntrackMetric{}
	}
	return conntrackMetric{
		uploadTotal:   metric.downloadTotal,
		downloadTotal: metric.uploadTotal,
		uploadRate:    metric.downloadRate,
		downloadRate:  metric.uploadRate,
	}
}

func diffConntrackCounter(current uint64, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func conntrackRate(delta uint64, elapsed time.Duration) uint64 {
	if delta == 0 || elapsed <= 0 {
		return 0
	}
	return uint64(float64(delta) / elapsed.Seconds())
}

func readConntrackCounters() (map[conntrackTuple]conntrackCounter, error) {
	file, err := openConntrackFile()
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	entries := make(map[conntrackTuple]conntrackCounter)
	for scanner.Scan() {
		tuple, counter, ok := parseConntrackLine(scanner.Text())
		if !ok {
			continue
		}
		entries[tuple] = counter
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func openConntrackFile() (*os.File, error) {
	var errs []error
	for _, path := range conntrackProcPaths {
		file, err := os.Open(path)
		if err == nil {
			return file, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func parseConntrackLine(line string) (conntrackTuple, conntrackCounter, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return conntrackTuple{}, conntrackCounter{}, false
	}

	network := strings.ToLower(fields[2])
	if network != "tcp" && network != "udp" {
		return conntrackTuple{}, conntrackCounter{}, false
	}

	var (
		sourceText      string
		destinationText string
		sourcePort      uint16
		destinationPort uint16
		sourceSeen      bool
		destinationSeen bool
		sportSeen       bool
		dportSeen       bool
		uploadBytes     uint64
		downloadBytes   uint64
		bytesSeen       int
		srcCount        int
		dstCount        int
		sportCount      int
		dportCount      int
	)

	for _, field := range fields {
		switch {
		case strings.HasPrefix(field, "src="):
			srcCount += 1
			if srcCount == 1 {
				sourceText = strings.TrimPrefix(field, "src=")
				sourceSeen = true
			}
		case strings.HasPrefix(field, "dst="):
			dstCount += 1
			if dstCount == 1 {
				destinationText = strings.TrimPrefix(field, "dst=")
				destinationSeen = true
			}
		case strings.HasPrefix(field, "sport="):
			sportCount += 1
			if sportCount == 1 {
				port, ok := parseConntrackPort(strings.TrimPrefix(field, "sport="))
				if !ok {
					return conntrackTuple{}, conntrackCounter{}, false
				}
				sourcePort = port
				sportSeen = true
			}
		case strings.HasPrefix(field, "dport="):
			dportCount += 1
			if dportCount == 1 {
				port, ok := parseConntrackPort(strings.TrimPrefix(field, "dport="))
				if !ok {
					return conntrackTuple{}, conntrackCounter{}, false
				}
				destinationPort = port
				dportSeen = true
			}
		case strings.HasPrefix(field, "bytes="):
			value, ok := parseConntrackUint(strings.TrimPrefix(field, "bytes="))
			if !ok {
				return conntrackTuple{}, conntrackCounter{}, false
			}
			bytesSeen += 1
			switch bytesSeen {
			case 1:
				uploadBytes = value
			case 2:
				downloadBytes = value
			}
		}
	}

	if !sourceSeen || !destinationSeen || !sportSeen || !dportSeen || bytesSeen < 2 {
		return conntrackTuple{}, conntrackCounter{}, false
	}

	sourceAddress, err := netip.ParseAddr(sourceText)
	if err != nil {
		return conntrackTuple{}, conntrackCounter{}, false
	}
	destinationAddress, err := netip.ParseAddr(destinationText)
	if err != nil {
		return conntrackTuple{}, conntrackCounter{}, false
	}

	return conntrackTuple{
			network:         network,
			sourceAddress:   sourceAddress,
			sourcePort:      sourcePort,
			destinationAddr: destinationAddress,
			destinationPort: destinationPort,
		}, conntrackCounter{
			upload:   uploadBytes,
			download: downloadBytes,
		}, true
}

func parseConntrackPort(text string) (uint16, bool) {
	value, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(value), true
}

func parseConntrackUint(text string) (uint64, bool) {
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}
