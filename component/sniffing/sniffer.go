/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/pool/bytes"
)

type Sniffer struct {
	// Stream
	stream    bool
	r         io.Reader
	dataReady chan struct{}
	dataError error
	dataErrMu sync.RWMutex
	closeOnce sync.Once

	// Common
	sniffed string
	buf     *bytes.Buffer
	readMu  sync.RWMutex
	ctx     context.Context
	cancel  func()

	// Packet
	data         [][]byte
	needMore     bool
	quicNextRead int
	quicCryptos  []*quicutils.CryptoFrameOffset
}

func NewStreamSniffer(r io.Reader, timeout time.Duration) *Sniffer {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	buffer := pool.GetBuffer()
	buffer.Grow(AssumedTlsClientHelloMaxLength)
	buffer.Reset()
	s := &Sniffer{
		stream:    true,
		r:         r,
		buf:       buffer,
		dataReady: make(chan struct{}, 1), // Use buffered channel to avoid blocking
		ctx:       ctx,
		cancel:    cancel,
	}
	return s
}

func NewPacketSniffer(data []byte, timeout time.Duration) *Sniffer {
	buffer := pool.GetBuffer()
	buffer.Write(data)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s := &Sniffer{
		stream:    false,
		r:         nil,
		buf:       buffer,
		data:      [][]byte{buffer.Bytes()},
		dataReady: make(chan struct{}, 1),
		ctx:       ctx,
		cancel:    cancel,
	}
	return s
}

type sniff func() (d string, err error)

func sniffGroup(sniffs ...sniff) (d string, err error) {
	for _, sniffer := range sniffs {
		d, err = sniffer()
		if err == nil {
			return NormalizeDomain(d), nil
		}
		if err != ErrNotApplicable {
			return "", err
		}
	}
	return "", ErrNotApplicable
}

func (s *Sniffer) SniffTcp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()
	// cancel context when sniffing completes to free resources
	defer s.cancel()
	
	s.readMu.Lock()
	defer s.readMu.Unlock()
	
	const maxRetries = 3 // Reduced retries for better performance
	retries := 0
	for {
		if retries >= maxRetries {
			return "", fmt.Errorf("%w: maximum sniff retries reached", ErrNotApplicable)
		}
		if s.stream {
			// Use buffered channel to avoid goroutine leak
			select {
			case s.dataReady <- struct{}{}:
			default:
			}
			
			go func() {
				_, err := s.buf.ReadFromOnce(s.r)
				if err != nil {
					s.dataErrMu.Lock()
					s.dataError = err
					s.dataErrMu.Unlock()
				}
				s.closeOnce.Do(func() { 
					select {
					case s.dataReady <- struct{}{}:
					default:
					}
				})
			}()
			
			// Wait for data or timeout
			select {
			case <-s.dataReady:
				s.dataErrMu.RLock()
				if s.dataError != nil {
					s.dataErrMu.RUnlock()
					return "", s.dataError
				}
				s.dataErrMu.RUnlock()
			case <-s.ctx.Done():
				return "", fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
			}
		} else {
			select {
			case s.dataReady <- struct{}{}:
			default:
			}
		}

		if s.buf.Len() == 0 {
			return "", ErrNotApplicable
		}

		d, err = sniffGroup(
			// Most sniffable traffic is TLS, thus we sniff it first.
			s.SniffTls,
			s.SniffHttp,
		)
		if errors.Is(err, ErrNeedMore) {
			// Reset for retry without recreating channel
			s.dataReady = make(chan struct{}, 1)
			s.closeOnce = sync.Once{}
			s.dataErrMu.Lock()
			s.dataError = nil
			s.dataErrMu.Unlock()
			retries++
			continue
		}
		return d, err
	}
}

func (s *Sniffer) SniffUdp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	// cancel context when sniffing completes to free resources
	defer s.cancel()
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Always ready.
	select {
	case s.dataReady <- struct{}{}:
	default:
	}

	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}

	return sniffGroup(
		s.SniffQuic,
	)
}

func (s *Sniffer) AppendData(data []byte) {
	s.needMore = false
	ori := s.buf.Len()
	s.buf.Write(data)
	s.data = append(s.data, s.buf.Bytes()[ori:])
}

func (s *Sniffer) Data() [][]byte {
	return s.data
}

func (s *Sniffer) NeedMore() bool {
	return s.needMore
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	<-s.dataReady

	s.readMu.RLock()
	defer s.readMu.RUnlock()
	
	s.dataErrMu.RLock()
	defer s.dataErrMu.RUnlock()
	if s.dataError != nil {
		n, _ = s.buf.Read(p)
		return n, s.dataError
	}

	if s.buf.Len() > 0 {
		// Read buf first.
		return s.buf.Read(p)
	}
	if !s.stream {
		return 0, io.EOF
	}
	return s.r.Read(p)
}

func (s *Sniffer) Close() (err error) {
	s.closeOnce.Do(func() {
		s.cancel()
		// Ensure buffer is always released
		if s.buf != nil {
			pool.PutBuffer(s.buf)
			s.buf = nil
		}
	})
	return nil
}
