//go:build linux

package control

import (
	"bytes"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"golang.org/x/sys/unix"
)

type LiveConnection struct {
	ID                 string    `json:"id"`
	Network            string    `json:"network"`
	State              string    `json:"state"`
	Source             string    `json:"source"`
	SourceAddress      string    `json:"sourceAddress"`
	SourcePort         uint16    `json:"sourcePort"`
	Destination        string    `json:"destination"`
	DestinationAddress string    `json:"destinationAddress"`
	DestinationPort    uint16    `json:"destinationPort"`
	Process            string    `json:"process"`
	PID                uint32    `json:"pid"`
	Outbound           string    `json:"outbound"`
	Direction          string    `json:"direction"`
	Mark               uint32    `json:"mark"`
	DSCP               uint8     `json:"dscp"`
	Must               bool      `json:"must"`
	HasRouting         bool      `json:"hasRouting"`
	Mac                string    `json:"mac"`
	LastSeen           time.Time `json:"lastSeen"`
}

type LiveConnectionsSnapshot struct {
	UpdatedAt   time.Time        `json:"updatedAt"`
	Total       int              `json:"total"`
	TCP         int              `json:"tcp"`
	UDP         int              `json:"udp"`
	Connections []LiveConnection `json:"connections"`
}

func (c *ControlPlane) LiveConnections(limit int) LiveConnectionsSnapshot {
	if limit <= 0 {
		limit = 200
	}

	bpf := c.currentBpf()
	if bpf == nil {
		return LiveConnectionsSnapshot{
			UpdatedAt:   time.Now(),
			Connections: []LiveConnection{},
		}
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return LiveConnectionsSnapshot{
			UpdatedAt:   time.Now(),
			Connections: []LiveConnection{},
		}
	}

	now := time.Now()
	nowMono := ts.Nano()
	unique := make(map[string]LiveConnection, limit)

	if bpf.TcpConnStateMap != nil {
		c.scanTcpConnections(unique, bpf.TcpConnStateMap, now, nowMono)
	}
	if bpf.UdpConnStateMap != nil {
		c.scanUdpConnections(unique, bpf.UdpConnStateMap, now, nowMono)
	}

	connections := make([]LiveConnection, 0, len(unique))
	summary := LiveConnectionsSnapshot{
		UpdatedAt:   now,
		Connections: connections,
	}
	for _, conn := range unique {
		connections = append(connections, conn)
		if conn.Network == "tcp" {
			summary.TCP++
		} else if conn.Network == "udp" {
			summary.UDP++
		}
	}

	slices.SortFunc(connections, func(a, b LiveConnection) int {
		switch {
		case a.LastSeen.After(b.LastSeen):
			return -1
		case a.LastSeen.Before(b.LastSeen):
			return 1
		default:
			if a.Network < b.Network {
				return -1
			}
			if a.Network > b.Network {
				return 1
			}
			if a.Source < b.Source {
				return -1
			}
			if a.Source > b.Source {
				return 1
			}
			if a.Destination < b.Destination {
				return -1
			}
			if a.Destination > b.Destination {
				return 1
			}
			return 0
		}
	})

	if len(connections) > limit {
		connections = connections[:limit]
	}
	summary.Total = len(unique)
	summary.Connections = connections
	return summary
}

func (c *ControlPlane) scanTcpConnections(unique map[string]LiveConnection, m *ebpf.Map, now time.Time, nowMono int64) {
	var (
		cursor    ebpf.MapBatchCursor
		keysOut   = make([]bpfTuplesKey, janitorBatchLookupSize)
		valuesOut = make([]bpfTcpConnState, janitorBatchLookupSize)
	)

	for {
		count, err := m.BatchLookup(&cursor, keysOut, valuesOut, nil)
		for i := 0; i < count; i++ {
			conn := c.liveConnectionFromTCP(keysOut[i], valuesOut[i], now, nowMono)
			upsertLiveConnection(unique, conn)
		}
		if err != nil {
			return
		}
	}
}

func (c *ControlPlane) scanUdpConnections(unique map[string]LiveConnection, m *ebpf.Map, now time.Time, nowMono int64) {
	var (
		cursor    ebpf.MapBatchCursor
		keysOut   = make([]bpfTuplesKey, janitorBatchLookupSize)
		valuesOut = make([]bpfUdpConnState, janitorBatchLookupSize)
	)

	for {
		count, err := m.BatchLookup(&cursor, keysOut, valuesOut, nil)
		for i := 0; i < count; i++ {
			conn := c.liveConnectionFromUDP(keysOut[i], valuesOut[i], now, nowMono)
			upsertLiveConnection(unique, conn)
		}
		if err != nil {
			return
		}
	}
}

func (c *ControlPlane) liveConnectionFromTCP(key bpfTuplesKey, state bpfTcpConnState, now time.Time, nowMono int64) LiveConnection {
	src := tuplesAddrPort(key.Sip.U6Addr8, key.Sport)
	dst := tuplesAddrPort(key.Dip.U6Addr8, key.Dport)
	lastSeen := monotonicLastSeenToWallTime(now, nowMono, int64(state.LastSeenNs))
	outbound := c.liveConnectionOutboundName(state.Meta.Data.Outbound)
	process := parseTaskComm(state.Pname)
	conn := LiveConnection{
		Network:            "tcp",
		State:              tcpConnectionStateName(state.State),
		Source:             RefineAddrPortToShow(src),
		SourceAddress:      src.Addr().String(),
		SourcePort:         src.Port(),
		Destination:        RefineAddrPortToShow(dst),
		DestinationAddress: dst.Addr().String(),
		DestinationPort:    dst.Port(),
		Process:            process,
		PID:                state.Pid,
		Outbound:           outbound,
		Direction:          liveConnectionDirection(state.IsWanIngressDirection),
		Mark:               state.Meta.Data.Mark,
		DSCP:               state.Meta.Data.Dscp,
		Must:               state.Meta.Data.Must != 0,
		HasRouting:         state.Meta.Data.HasRouting != 0,
		Mac:                liveConnectionMacString(state.Mac),
		LastSeen:           lastSeen,
	}
	conn.ID = canonicalLiveConnectionID(conn.Network, conn.Source, conn.Destination, conn.Process, conn.PID, conn.Outbound)
	return conn
}

func (c *ControlPlane) liveConnectionFromUDP(key bpfTuplesKey, state bpfUdpConnState, now time.Time, nowMono int64) LiveConnection {
	src := tuplesAddrPort(key.Sip.U6Addr8, key.Sport)
	dst := tuplesAddrPort(key.Dip.U6Addr8, key.Dport)
	lastSeen := monotonicLastSeenToWallTime(now, nowMono, int64(state.LastSeenNs))
	outbound := c.liveConnectionOutboundName(state.Meta.Data.Outbound)
	process := parseTaskComm(state.Pname)
	conn := LiveConnection{
		Network:            "udp",
		State:              "active",
		Source:             RefineAddrPortToShow(src),
		SourceAddress:      src.Addr().String(),
		SourcePort:         src.Port(),
		Destination:        RefineAddrPortToShow(dst),
		DestinationAddress: dst.Addr().String(),
		DestinationPort:    dst.Port(),
		Process:            process,
		PID:                state.Pid,
		Outbound:           outbound,
		Direction:          liveConnectionDirection(state.IsWanIngressDirection),
		Mark:               state.Meta.Data.Mark,
		DSCP:               state.Meta.Data.Dscp,
		Must:               state.Meta.Data.Must != 0,
		HasRouting:         state.Meta.Data.HasRouting != 0,
		Mac:                liveConnectionMacString(state.Mac),
		LastSeen:           lastSeen,
	}
	conn.ID = canonicalLiveConnectionID(conn.Network, conn.Source, conn.Destination, conn.Process, conn.PID, conn.Outbound)
	return conn
}

func upsertLiveConnection(unique map[string]LiveConnection, conn LiveConnection) {
	existing, ok := unique[conn.ID]
	if !ok || conn.LastSeen.After(existing.LastSeen) {
		unique[conn.ID] = conn
	}
}

func tuplesAddrPort(addr [16]uint8, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), common.Ntohs(port))
}

func monotonicLastSeenToWallTime(now time.Time, nowMono int64, lastSeenMono int64) time.Time {
	age := nowMono - lastSeenMono
	if age < 0 {
		age = 0
	}
	return now.Add(-time.Duration(age))
}

func liveConnectionDirection(isWanIngress bool) string {
	if isWanIngress {
		return "wan-ingress"
	}
	return "lan-egress"
}

func tcpConnectionStateName(state uint8) string {
	switch state {
	case 1:
		return "closing"
	default:
		return "established"
	}
}

func canonicalLiveConnectionID(network, source, destination, process string, pid uint32, outbound string) string {
	a := source
	b := destination
	if a > b {
		a, b = b, a
	}
	return network + "|" + a + "|" + b + "|" + process + "|" + strconv.FormatUint(uint64(pid), 10) + "|" + outbound
}

func parseTaskComm(comm [16]uint8) string {
	text := bytes.TrimRight(comm[:], "\x00")
	if len(text) == 0 {
		return "-"
	}
	return string(text)
}

func liveConnectionMacString(mac [6]uint8) string {
	if mac == [6]uint8{} {
		return "-"
	}
	return Mac2String(mac[:])
}

func (c *ControlPlane) liveConnectionOutboundName(raw uint8) string {
	index := consts.OutboundIndex(raw)
	if index.IsReserved() {
		return index.String()
	}
	offset := int(index - consts.OutboundUserDefinedMin)
	if offset >= 0 && offset < len(c.outbounds) && c.outbounds[offset] != nil && c.outbounds[offset].Name != "" {
		return c.outbounds[offset].Name
	}
	return index.String()
}
