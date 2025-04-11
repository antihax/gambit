package drivers

import (
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/pkg/muxconn"
	"github.com/lunixbochs/struc"
)

type mikrotikRouterOS struct {
}

func init() {
	AddDriver(&mikrotikRouterOS{})
}

// [TODO] Find good pattern
func (s *mikrotikRouterOS) Patterns() [][]byte {
	return [][]byte{
		[]byte("/login\x00"),
		{0x01, 0x00, 0x35, 0x4D},
	}
}

func (s *mikrotikRouterOS) ServeTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {
			glob := gctx.GetGlobalFromContext(mux.Context, "mikrotik")

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				for {

					hdr := &mikrotikRouterOSFrame{}
					err := struc.Unpack(conn, hdr)
					if err != nil {
						glob.LogError(err)
						return
					}

					// save session data
					glob.NewSession(conn.Sequence(), StoreHash(conn.Snapshot(), glob.Store)).
						Logger.Info().Msg("Mikrotik RouterOS")
				}
			}(mux)
		}
	}
}

type mikrotikRouterOSFrame struct {
	Length  uint8 `struc:"sizeof=Payload"`
	Payload []byte
	End     uint8
}
