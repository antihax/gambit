package muxconn

import (
	"errors"
	"net"
)

// Proxy transfers accepted connections from one listener to another services listener
// Useful for inserting MuxConn or ModConn
type Proxy struct {
	connCh chan net.Conn
}

func NewProxy(bufferSize int) Proxy {
	return Proxy{
		connCh: make(chan net.Conn, bufferSize),
	}
}

func (l Proxy) InjectConn(c net.Conn) {
	l.connCh <- c
}

func (l Proxy) Accept() (net.Conn, error) {
	c, ok := <-l.connCh
	if !ok {
		return nil, errors.New("proxy closed")
	}
	return c, nil
}

func (l Proxy) Close() error {
	close(l.connCh)
	return nil
}

func (l Proxy) Addr() net.Addr {
	return &net.TCPAddr{}
}
