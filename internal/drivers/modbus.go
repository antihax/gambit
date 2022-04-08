package drivers

import (
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/lunixbochs/struc"
)

type modbus struct {
}

func init() {

	AddDriver(&modbus{})
}

// [TODO] Find good pattern
func (s *modbus) Patterns() [][]byte {
	return [][]byte{}
}

func (s *modbus) ServeTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {
			glob := gctx.GetGlobalFromContext(mux.Context, "modbus")
			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				for {
					hdr := &modbusHeaderV1{}
					err := struc.Unpack(conn, hdr)
					if err != nil || hdr.Length == 0 || hdr.Length > 260 {
						glob.LogError(err)
						return
					}
				}
			}(mux)
		}
	}
}

type modbusHeaderV1 struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
}
