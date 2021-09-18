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
