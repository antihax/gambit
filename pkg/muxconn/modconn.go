package muxconn

import (
	"net"
)

type PreReadFunc func(conn net.Conn, p []byte) (int, bool)
type ReadFunc func(conn net.Conn, p []byte, n int) (int, error)
type WriteFunc func(conn net.Conn, p []byte) ([]byte, error)

// ModConn wraps a net.Conn and allows hooking read and write to modify the data.
// Useful for services which do not allow access to their underlying net.Conn.
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
