// Copyright 2016 The CMux Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

// Package muxconn wraps net.Conn and allows sniffing without consumption.
// Blatantly stolen from https://github.com/soheilhy/cmux/blob/master/cmux.go because their version is not fully exported...
package muxconn

import (
	"io"
	"net"

	"github.com/antihax/pass/internal/store"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type errListenerClosed string

func (e errListenerClosed) Error() string   { return string(e) }
func (e errListenerClosed) Temporary() bool { return false }
func (e errListenerClosed) Timeout() bool   { return false }

// ErrListenerClosed is returned from muxListener.Accept when the underlying
// listener is closed.
var ErrListenerClosed = errListenerClosed("mux: listener closed")

type MuxListener struct {
	net.Listener
	ConnCh chan net.Conn
	Logger zerolog.Logger
}

func (l MuxListener) Accept() (net.Conn, error) {
	c, ok := <-l.ConnCh
	if !ok {
		return nil, ErrListenerClosed
	}
	return c, nil
}

// MuxConn wraps a net.Conn and provides transparent sniffing of connection data.
type MuxConn struct {
	net.Conn
	buf       BufferedReader
	uuid      string
	hash      string
	sequence  int
	logger    zerolog.Logger
	StoreChan chan store.File
}

// NewMuxConn returns a new sniffable connection.
func NewMuxConn(c net.Conn, logger zerolog.Logger, storeChan chan store.File) *MuxConn {
	return &MuxConn{
		Conn:      c,
		buf:       BufferedReader{source: c},
		uuid:      uuid.NewString(),
		logger:    logger,
		StoreChan: storeChan,
	}
}

// From the io.Reader documentation:
//
// When Read encounters an error or end-of-file condition after
// successfully reading n > 0 bytes, it returns the number of
// bytes read.  It may return the (non-nil) error from the same call
// or return the error (and n == 0) from a subsequent call.
// An instance of this general case is that a Reader returning
// a non-zero number of bytes at the end of the input stream may
// return either err == EOF or err == nil.  The next Read should
// return 0, EOF.
func (m *MuxConn) Read(p []byte) (int, error) {
	return m.buf.Read(p)
}

// SetHash based on the first bytes
// [TODO] Improve this, it's backwards to set this
func (m *MuxConn) SetHash(hash string) {
	m.hash = hash
}

// GetHash for the connection
func (m *MuxConn) GetHash() string {
	return m.hash
}

// GetUUID for the connection
func (m *MuxConn) GetUUID() string {
	return m.uuid
}

// Sequence returns the next sequence number (increments automatically)
func (m *MuxConn) Sequence() int {
	m.sequence++
	return m.sequence
}

func (m *MuxConn) GetLogger() zerolog.Logger {
	return m.logger.With().Str("uuid", m.uuid).Str("hash", m.hash).Logger()
}

func (m *MuxConn) StartSniffing() io.Reader {
	m.buf.reset(true)
	return &m.buf
}

func (m *MuxConn) DoneSniffing() {
	m.buf.reset(false)
}
