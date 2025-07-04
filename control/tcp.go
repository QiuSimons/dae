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
	"github.com/daeuniverse/outbound/netproxy"
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
		IpVersion: consts.IpVersionFromAddr(dst.Addr()),
		IsDns:     false,
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
	rConn, err := dialOption.Dialer.DialContext(ctx, common.MagicNetwork("tcp", dialOption.Mark), dialOption.DialTarget)
	if err != nil {
		// TODO: UDP 是不是也有Direct Outbound出问题的情况?
		// TODO: Control Plane Routing?
		// TODO: 哪些错误说明节点不工作或GFW在工作?
		// TCP: Connection Reset / Connection Refused
		var netErr net.Error
		if errors.As(err, &netErr) && !netErr.Temporary() {
			err = oops.
				In("DialContext").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Property().Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", domain).
				With("routingResult", routingResult).
				Wrapf(err, "failed to DialContext")
			dialOption.Dialer.ReportUnavailable(networkType, err)
			if !dialOption.OutboundIndex.IsReserved() {
				return err
			}
		}
		return nil
	}

	// Relay
	defer rConn.Close()
	if err := RelayTCP(sniffer, rConn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && !netErr.Temporary() && dialOption.Dialer.MustGetAlive(networkType) {
			err = oops.
				In("RelayTCP").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Property().Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", domain).
				With("routingResult", routingResult).
				Wrapf(err, "failed to RelayTCP")
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

func relayDirection(dst, src_ netproxy.Conn) error {
	// As `io.Copy` uses a 32KB buffer, we create a buffer of the same size.
	// See https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/io/io.go;l=419
	bufPtr := pool.GetFullCap(1024 * 32) // 32KB
	defer bufPtr.Put()

	src := &ConnWithReadTimeout{Conn: src_}
	_, err := io.CopyBuffer(dst, src, bufPtr)

	// For Quic
	if writeCloser, ok := dst.(WriteCloser); ok {
		_ = writeCloser.CloseWrite()
	}

	if err != nil {
		dst.SetDeadline(time.Now())
	}

	return err
}

// Error1 is the error from lConn to rConn
// Error2 is the error from rConn to lConn
// TODO: 引入 ctx, 在 dialer 不可用时取消 relay
// 进一步的, 给 lConn 发送 rst
func RelayTCP(lConn, rConn netproxy.Conn) error {
	errCh := make(chan error, 1)

	var netErr net.Error

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
		case
			strings.HasSuffix(err.Error(), "canceled by remote with error code 0"), // rConn closed
			strings.Contains(err.Error(), "read:"):                                 // lConn Read
			err = nil
		default:
			err = oops.
				In("lConn -> rConn Relay").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrap(err)
		}

	}
	if err2 != nil { // r -> l
		switch {
		case strings.Contains(err2.Error(), "write:"): // lConn Write
			err2 = nil
		default:
			err2 = oops.
				In("rConn -> lConn Relay").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				Wrap(err2)
		}
	}

	return oops.Join(err, err2)
}
