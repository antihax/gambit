package drivers

import (
	"log"
	"net"
	"strconv"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/lunixbochs/struc"
	"github.com/rs/zerolog"
)

func init() {
	// this may be too aggressive
	AddDriver([]byte{3, 0, 0}, &rdp{})
}

type rdp struct {
	logger zerolog.Logger
}

func (s *rdp) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return err
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {
			s.logger = gctx.GetLoggerFromContext(mux.Context).With().Str("driver", "rdp").Logger()
			storeChan := gctx.GetStoreFromContext(mux.Context)

			go func(conn net.Conn) {
				sequence := mux.Sequence()
				defer conn.Close()
				hdr := &TPKTHeader{}

				// Get the header
				struc.Unpack(conn, hdr)
				b := make([]byte, hdr.Size-7)

				struc.Unpack(conn, &b)
				s.logger.Warn().Int("sequence", sequence).Msg("rdp knock")
				// save session data
				storeChan <- store.File{
					Filename: mux.GetUUID() + "-" + strconv.Itoa(sequence),
					Location: "sessions",
					Data:     b,
				}
			}(conn)
		}
	}
}

type TPKTHeader struct {
	Version  uint8
	Reserved uint8
	Size     uint16
}

type TPDU struct {
	Length                uint8
	ConnectionRequestCode uint8
	DstRef                [2]uint8
	SrcRef                [2]uint8
	ClassOption           uint8
}

type RDPNegReq struct {
	Type               byte
	Flags              byte
	Length             [2]byte
	RequestedProtocols [4]byte
}
