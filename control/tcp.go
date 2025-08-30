/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/pool"
	"github.com/samber/oops"
	"golang.org/x/sys/unix"
)

func (c *ControlPlane) handleConn(lConn net.Conn) error {
	defer lConn.Close()

	// Sniff target domain.
	sniffer := sniffing.NewConnSniffer(lConn, c.sniffingTimeout)
	// ConnSniffer should be used later, so we cannot close it now.
	defer sniffer.Close()
	domain, err := sniffer.SniffTcp()
	if err != nil && !sniffing.IsSniffingError(err) {
		// We ignore lConn errors or temporary network errors
		var netErr net.Error
		if errors.As(err, &netErr) {
			return nil
		}
		return oops.Wrapf(err, "Sniff Failed")
	}

	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		return oops.Wrapf(err, "failed to retrieve target info %v", dst.String())
	}
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

	// Route
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	dialOption, err := c.RouteDialOption(&RouteParam{
		routingResult: routingResult,
		networkType:   networkType,
		Domain:        domain,
		Src:           src,
		Dest:          dst,
	})
	if err != nil {
		return err
	}

	// Dial
	LogDial(src, dst, domain, dialOption, networkType, routingResult)
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	start := time.Now()
	rConn, err := dialOption.Dialer.DialContext(ctx, "tcp", dialOption.DialTarget)
	elapsed := time.Since(start).Seconds()

	DialLatency.Observe(elapsed)
	ActiveConnections.Inc()
	ActiveConnectionsTCP.Inc()
	TotalConnections.Inc()
	dialOption.Dialer.DialLatency.Observe(elapsed)
	dialOption.Dialer.TotalConnections.Inc()
	dialOption.Dialer.ActiveConnections.Inc()
	dialOption.Dialer.ActiveConnectionsTCP.Inc()

	defer func() {
		ActiveConnections.Dec()
		ActiveConnectionsTCP.Dec()
		dialOption.Dialer.ActiveConnections.Dec()
		dialOption.Dialer.ActiveConnectionsTCP.Dec()
	}()
	if err != nil {
		// TODO: UDP 是不是也有Direct Outbound出问题的情况?
		// TODO: Control Plane Routing?
		// TODO: 哪些错误说明节点不工作或GFW在工作?
		// TCP: Connection Reset / Connection Refused
		netErr, ok := IsNetError(err)
		err = oops.
			In("DialContext").
			With("Is NetError", ok).
			With("Is Temporary", netErr != nil && netErr.Temporary()).
			With("Is Timeout", netErr != nil && netErr.Timeout()).
			With("Outbound", dialOption.Outbound.Name).
			With("Dialer", dialOption.Dialer.Property().Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			Wrapf(err, "failed to DialContext")
		if !ok {
			return err
		} else if !netErr.Timeout() {
			dialOption.Dialer.ReportUnavailable(networkType, err)
			if !dialOption.OutboundIndex.IsReserved() {
				return err
			}
		}
		return nil
	}

	defer rConn.Close()

	// Relay
	if err := RelayTCP(sniffer, rConn); err != nil {
		netErr, ok := IsNetError(err)
		err = oops.
			In("RelayTCP").
			With("Is NetError", ok).
			With("Is Temporary", netErr != nil && netErr.Temporary()).
			With("Is Timeout", netErr != nil && netErr.Timeout()).
			With("Outbound", dialOption.Outbound.Name).
			With("Dialer", dialOption.Dialer.Property().Name).
			With("src", src.String()).
			With("dst", dst.String()).
			With("domain", domain).
			Wrapf(err, "failed to RelayTCP")
		if !ok {
			return err
		} else if !netErr.Timeout() {
			dialOption.Dialer.ReportUnavailable(networkType, err)
			if !dialOption.OutboundIndex.IsReserved() {
				return err
			}
		}
	}
	// case strings.HasSuffix(err.Error(), "write: broken pipe"),
	// 	strings.HasSuffix(err.Error(), "i/o timeout"),
	// 	strings.HasPrefix(err.Error(), "EOF"),
	// 	strings.HasSuffix(err.Error(), "connection reset by peer"),
	// 	strings.HasSuffix(err.Error(), "canceled by local with error code 0"),
	// 	strings.HasSuffix(err.Error(), "canceled by remote with error code 0"):
	return nil
}

type WriteCloser interface {
	CloseWrite() error
}

type ConnWithReadTimeout struct {
	net.Conn
}

func (c *ConnWithReadTimeout) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(consts.DefaultReadTimeout))
	return c.Conn.Read(p)
}

func relayDirection(dst, src_ net.Conn) error {
	// As `io.Copy` uses a 32KB buffer, we create a buffer of the same size.
	// See https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/io/io.go;l=419
	bufPtr := pool.GetBuffer(1024 * 32) // 32KB
	defer pool.PutBuffer(bufPtr)

	src := &ConnWithReadTimeout{Conn: src_}
	_, err := io.CopyBuffer(dst, src, bufPtr)

	if err != nil {
		dst.SetReadDeadline(time.Now())
	}

	return err
}

// Error1 is the error from lConn to rConn
// Error2 is the error from rConn to lConn
// TODO: 引入 ctx, 在 dialer 不可用时取消 relay
// 进一步的, 给 lConn 发送 rst
func RelayTCP(lConn, rConn net.Conn) error {
	errCh := make(chan error, 1)

	// Start relay goroutine from rConn to lConn
	go func() {
		err := relayDirection(lConn, rConn)
		errCh <- err
	}()
	// Do relay from lConn to rConn
	err := relayDirection(rConn, lConn)
	err2 := <-errCh

	// We ignore lConn errors or temporary network errors
	// TODO: Why get EOF as an error?
	if err != nil { // l -> r
		switch {
		case err == io.EOF,
			strings.HasSuffix(err.Error(), "canceled by remote with error code 0"), // rConn closed
			strings.Contains(err.Error(), "read:"):                                 // lConn Read
			err = nil
		default:
			err = oops.In("lConn -> rConn Relay").Wrap(err)
		}

	}
	if err2 != nil { // r -> l
		switch {
		case strings.Contains(err2.Error(), "write:"): // lConn Write
			err2 = nil
		default:
			err2 = oops.In("rConn -> lConn Relay").Wrap(err2)
		}
	}

	return oops.Join(err, err2)
}
