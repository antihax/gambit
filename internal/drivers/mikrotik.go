package drivers

import (
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/lunixbochs/struc"
	"github.com/rs/zerolog"
)

type mikrotikRouterOS struct {
	logger zerolog.Logger
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
			s.logger = gctx.GetGlobalFromContext(mux.Context).Logger.With().Str("driver", "mikrotik").Logger()
			storeChan := gctx.GetGlobalFromContext(mux.Context).Store

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				sequence := conn.Sequence()
				for {
					hdr := &mikrotikRouterOS_Frame{}
					err := struc.Unpack(conn, hdr)
					if err != nil {
						return
					}

					// save session data
					hash := StoreHash(conn.Snapshot(), storeChan)
					s.logger.Debug().Int("sequence", sequence).Str("phash", hash).Msg("Mikrotik RouterOS")
				}
			}(mux)
		}
	}
}

type mikrotikRouterOS_Frame struct {
	Length  uint8 `struc:"sizeof=Payload"`
	Payload []byte
	End     uint8
}
