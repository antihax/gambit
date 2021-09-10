package drivers

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/lunixbochs/struc"
	"github.com/rs/zerolog"
)

type modbus struct {
	logger zerolog.Logger
}

func init() {

	AddDriver(&modbus{})
}

// [TODO] Find good pattern
func (s *modbus) Patterns() [][]byte {

	return [][]byte{}
}

func (s *modbus) ServeTCP(ln net.Listener) error {

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return err
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {
			s.logger = gctx.GetLoggerFromContext(mux.Context).With().Str("driver", "modbus").Logger()

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				for {
					hdr := &modbus_HeaderV1{}
					err := struc.Unpack(conn, hdr)
					if err != nil || hdr.Length == 0 || hdr.Length > 260 {
						fmt.Printf("err %+v\n", err)
						return
					}
					fmt.Printf("%+v\n", hdr)
				}
			}(mux)
		}
	}
}

type modbus_HeaderV1 struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
}
