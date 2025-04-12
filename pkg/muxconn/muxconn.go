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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
)

// MuxConn wraps a net.Conn and provides transparent sniffing of connection data.
type MuxConn struct {
	net.Conn
	pcap       *pcapgo.NgWriter
	pcapBuffer bytes.Buffer
	buf        BufferedReader
	uuid       string
	sequence   int
	Context    context.Context
}

// NewMuxConn returns a new sniffable connection.
func NewMuxConn(ctx context.Context, c net.Conn) (*MuxConn, error) {
	// setup pcapng wrapper
	buffer := bytes.Buffer{}
	writer := bufio.NewWriter(&buffer)
	pcap, err := pcapgo.NewNgWriter(writer, layers.LinkTypeEthernet)
	if err != nil {
		return nil, err
	}

	// Build connection
	conn := &MuxConn{
		Conn:       c,
		pcap:       pcap,
		pcapBuffer: buffer,
		buf:        BufferedReader{source: c},
		uuid:       uuid.NewString(),
		Context:    ctx,
	}

	return conn, nil
}

// When Read encounters an error or end-of-file condition after
// successfully reading n > 0 bytes, it returns the number of
// bytes read.  It may return the (non-nil) error from the same call
// or return the error (and n == 0) from a subsequent call.
// An instance of this general case is that a Reader returning
// a non-zero number of bytes at the end of the input stream may
// return either err == EOF or err == nil.  The next Read should
// return 0, EOF.
func (m *MuxConn) Read(p []byte) (int, error) {
	n, err := m.buf.Read(p)
	if err != nil {
		return n, err
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		Length:         len(p),
		CaptureLength:  len(p),
		InterfaceIndex: 0,
	}

	err = m.pcap.WritePacket(ci, p)
	if err != nil {
		fmt.Println(err)
		return n, err
	}

	err = m.pcap.Flush()
	if err != nil {
		fmt.Println(err)
		return n, err
	}
	return n, err
}

// ReadFrom PacketConn interface
func (m *MuxConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := m.buf.Read(p)
	if err != nil {
		return n, m.RemoteAddr(), err
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		Length:         len(p),
		CaptureLength:  len(p),
		InterfaceIndex: 0,
	}

	err = m.pcap.WritePacket(ci, p)
	if err != nil {
		fmt.Println(err)
		return n, m.RemoteAddr(), err
	}

	err = m.pcap.Flush()
	if err != nil {
		fmt.Println(err)
		return n, m.RemoteAddr(), err
	}

	return n, m.RemoteAddr(), err
}

// WriteTo PacketConn interface, ignores address
func (m *MuxConn) WriteTo(p []byte, a net.Addr) (int, error) {
	return m.Write(p)
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

func (m *MuxConn) StartSniffing() io.Reader {
	m.buf.Reset(true)
	return &m.buf
}

func (m *MuxConn) Reset() {
	m.buf.Reset(true)
}

func (m *MuxConn) DoneSniffing() {
	m.buf.Reset(false)
}

func (m *MuxConn) Snapshot() []byte {
	return m.buf.Snapshot()
}

func (m *MuxConn) NumWritten() int {
	return m.buf.bufferWritten
}

func (m *MuxConn) BufferSize() int {
	return m.buf.bufferSize
}

func (m *MuxConn) Close() error {

	if m == nil {
		return errors.New("Nil MuxConn")
	}
	m.pcap.Flush()

	return m.Conn.Close()
}
