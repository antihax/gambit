package muxconn

import (
	"errors"
	"net"
)

// MuxProxy transfers accepted connections from one listener to another services listener
// Useful for inserting MuxConn or ModConn
type MuxProxy struct {
	ConnCh chan net.Conn
}

func (l MuxProxy) Accept() (net.Conn, error) {
	c, ok := <-l.ConnCh
	if !ok {
		return nil, errors.New("proxy closed")
	}
	return c, nil
}

func (l MuxProxy) Close() error {
	close(l.ConnCh)
	return nil
}

func (l MuxProxy) Addr() net.Addr {
	return &net.TCPAddr{}
}
