package main

import (
	"net"

	"github.com/antihax/pass/pkg/conman"
	"github.com/antihax/pass/pkg/probe"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	conn, _ := net.ListenIP("ip4:tcp", nil)
	conman := conman.NewConMan()

	// prelisten everything
	for i := uint16(1); i < 65535; i++ {
		_, err := conman.CreateTCPListener(i)
		if err != nil {
			log.Debug().Err(err).Msg("creating socket")
		}
	}

	for {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil { // get out if we error
			log.Debug().Err(err).
				Str("address", addr.String()).
				Msg("reading socket")
			continue
		}

		pkt := &probe.TCPPacket{}
		pkt.Decode(buf[:n])
		if pkt.Flags&probe.SYN != 0 {
			known, err := conman.CreateTCPListener(pkt.DestPort)
			if err != nil {
				log.Debug().Err(err).Msg("creating socket")
			}
			if !known {
				log.Debug().Msgf("started tcp server: %v", pkt.DestPort)
			}
		}
	}
}
