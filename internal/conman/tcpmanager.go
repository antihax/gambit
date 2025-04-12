package conman

import (
	"net"

	"github.com/antihax/gambit/pkg/probe"
)

// tcpManager listens for unknown packets and fires up listeners to handle
// in the future
func (s *ConnectionManager) tcpManager() {
	conn, err := net.ListenIP("ip:tcp", nil)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			// read max MTU if available
			buf := make([]byte, 4096)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil { // get out if we error
				s.logger.Trace().Err(err).
					Str("network", "tcp").
					Str("address", addr.String()).
					Msg("reading socket")
				continue
			}

			pkt := &probe.TCPPacket{}
			pkt.Decode(buf[:n])
			if pkt.Flags&probe.SYN != 0 {
				// fire up listener, kernel will take over future requests.
				known, err := s.CreateTCPListener(pkt.DestPort)
				if err != nil {
					s.logger.Trace().Err(err).Msg("creating socket")
				}
				if !known {
					s.logger.Trace().Msgf("started tcp server: %v", pkt.DestPort)
				}
			}
		}
	}()
}
