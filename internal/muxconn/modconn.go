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
	"net"
)

type PreReadFunc func(conn net.Conn, p []byte) (int, bool)
type ReadFunc func(conn net.Conn, p []byte, n int) (int, error)
type WriteFunc func(conn net.Conn, p []byte) ([]byte, error)

type ModConn struct {
	net.Conn
	PreReadDecorate PreReadFunc
	ReadDecorate    ReadFunc
	WriteDecorate   WriteFunc
}

func NewModConn(c net.Conn, p PreReadFunc, r ReadFunc, w WriteFunc) *ModConn {
	return &ModConn{
		Conn:            c,
		PreReadDecorate: p,
		ReadDecorate:    r,
		WriteDecorate:   w,
	}
}

func (m *ModConn) GetConn() net.Conn {
	return m.Conn
}

func (m *ModConn) Read(p []byte) (int, error) {
	if m.PreReadDecorate != nil {
		n, skip := m.PreReadDecorate(m, p)
		if skip {
			return n, nil
		}
	}
	n, e := m.Conn.Read(p)
	if e != nil {
		return n, e
	}
	if m.ReadDecorate != nil {
		n, e = m.ReadDecorate(m, p, n)
		if e != nil {
			return n, e
		}
	}
	return n, e
}

func (m *ModConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, e := m.Read(p)
	return n, m.RemoteAddr(), e
}

func (m *ModConn) Write(p []byte) (int, error) {
	if m.WriteDecorate != nil {
		b, e := m.WriteDecorate(m, p)
		if e != nil {
			return 0, e
		}
		p = b
	}

	return m.Conn.Write(p)
}

func (m *ModConn) WriteTo(p []byte, a net.Addr) (int, error) {
	return m.Write(p)
}
