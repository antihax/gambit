package drivers

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/lunixbochs/struc"
	"github.com/rs/zerolog"
)

func init() {

	AddDriver(&rdp{})
}

// [TODO] this may be too aggressive
func (s *rdp) Patterns() [][]byte {
	return [][]byte{
		{3, 0, 0},
	}
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
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				sequence := mux.Sequence()
				defer conn.Close()
				hdr := &rdp_TPKTHeader{}

				// Get the header
				struc.Unpack(conn, hdr)
				b := make([]byte, hdr.Size-7)
				struc.Unpack(conn, &b)

				fmt.Printf("\n%+v\n\n", b)
				s.logger.Debug().Int("sequence", sequence).Msg("rdp knock")
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

type rdp_TPKTHeader struct {
	Version  uint8
	Reserved uint8
	Size     uint16
}

type rdp_TPDU struct {
	Length                uint8
	ConnectionRequestCode uint8
	DstRef                uint16
	SrcRef                uint16
	ClassOption           uint8
}

type rdp_RDPNegReq struct {
	Type               uint8
	Flags              uint8
	Length             uint16
	RequestedProtocols uint32
}
