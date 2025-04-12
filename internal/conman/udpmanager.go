package conman

import (
	"bytes"
	"net"

	"github.com/lunixbochs/struc"
)

// UDPHeader is the header for the UDP packets
type UDPHeader struct {
	Source      uint16
	Destination uint16
	Length      uint16
	Checksum    uint16
}

// udpManager listens for unknown packets and fires up listeners to handle
// in the future
func (s *ConnectionManager) udpManager() {
	conn, err := net.ListenIP("ip4:udp", nil)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			// read max MTU if available
			buf := make([]byte, 1500)
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				s.logger.Trace().Err(err).
					Str("network", "udp").
					Str("address", addr.String()).
					Msg("reading socket")
			}

			reader := bytes.NewReader(buf)
			header := UDPHeader{}

			struc.Unpack(reader, &header)
			if s.config.PortIgnored(header.Destination) {
				continue
			}
			// see if we match a rule and transfer the connection to the driver

			// fire up listener, kernel will take over future requests.
			known, err := s.createListener(header.Destination, "udp")
			if err != nil {
				s.logger.Trace().Err(err).Msg("creating socket")
			}
			if !known {
				s.logger.Trace().Msgf("started udp server: %v", header.Destination)
			}

		}
	}()
}
