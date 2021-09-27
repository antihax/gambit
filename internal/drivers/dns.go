package drivers

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/miekg/dns"
)

type decoratedWriter struct {
	dns.Writer
	EvilDNS *evildns
}

func (dr *decoratedWriter) Write(p []byte) (int, error) {
	n, e := dr.Writer.Write(p)
	return n, e
}

type decoratedReader struct {
	dns.Reader
	EvilDNS *evildns
}

func (dr *decoratedReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	b, e := dr.Reader.ReadTCP(conn, timeout)
	if len(b) > 0 {
		if mux, ok := conn.(*muxconn.ModConn).GetConn().(*muxconn.MuxConn); ok {
			dr.EvilDNS.Glob = gctx.GetGlobalFromContext(mux.Context, "dns")

			// save session data
			dr.EvilDNS.Glob.NewSession(mux.Sequence(), StoreHash(mux.Snapshot(), dr.EvilDNS.Glob.Store)).
				Logger.Info().Msg("dns")
		}
	}
	return b, e
}

func (dr *decoratedReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	b, s, e := dr.Reader.ReadUDP(conn, timeout)
	return b, s, e
}

func init() {
	s := &evildns{
		Server: &dns.Server{},
		Proxy:  muxconn.NewProxy(100),
	}
	AddDriver(s)
	dns.DefaultMsgAcceptFunc = s.MsgAcceptFunc

	s.Server.Listener = s.Proxy
	s.Server.Handler = dns.HandlerFunc(s.Handler)
	s.Server.DecorateReader = func(r dns.Reader) dns.Reader {
		return &decoratedReader{Reader: r, EvilDNS: s}
	}
	s.Server.DecorateWriter = func(w dns.Writer) dns.Writer {
		return &decoratedWriter{Writer: w, EvilDNS: s}
	}
	go func() {
		if err := s.Server.ActivateAndServe(); err != nil {
			panic(err)
		}
	}()
}

type evildns struct {
	Server *dns.Server
	Proxy  muxconn.Proxy
	Hash   string
	PHash  string
	Glob   *gctx.GlobalUtils
}

func (s *evildns) Patterns() [][]byte {
	return [][]byte{
		{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

func (s *evildns) udpToTCP(conn net.Conn, p []byte) (int, bool) {
	// length packet for TCP
	if len(p) == 2 {
		// look ahead at the muxconn buffer to hack in packet size
		if mux, ok := conn.(*muxconn.ModConn).GetConn().(*muxconn.MuxConn); ok {
			binary.BigEndian.PutUint16(p[0:], uint16(mux.NumWritten()))
			return 2, true
		}
	}

	// either normal or snafu
	return len(p), false
}

func (s *evildns) tcpToUDP(conn net.Conn, p []byte) ([]byte, error) {
	// lop off the length
	return p[2:], nil
}

func (s *evildns) ServeUDP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		modcon := muxconn.NewModConn(
			conn,
			s.udpToTCP,
			nil,
			s.tcpToUDP,
		)

		s.Proxy.InjectConn(modcon)
	}
}

func (s *evildns) ServeTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		modcon := muxconn.NewModConn(
			conn,
			nil,
			nil,
			nil,
		)
		s.Proxy.InjectConn(modcon)
	}
}

// [TODO] expand to serve other types
func (s *evildns) Handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "*.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
		A:   net.ParseIP(gctx.IPAddress),
	}

	m.Answer = append(m.Answer, rr)

	s.Glob.Logger.Debug().Str("dig", r.String()).Msg("dns dig")

	if m.Question[0].Name == "." {
		m.Truncated = true
		buf, _ := m.Pack()
		w.Write(buf[:len(buf)/2])
		return
	}
	w.WriteMsg(m)
}

func (s *evildns) MsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	return dns.MsgAccept
}
