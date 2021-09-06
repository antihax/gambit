package drivers

import (
	"bytes"
	"fmt"
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

func (s *mikrotikRouterOS) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return err
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {
			s.logger = gctx.GetLoggerFromContext(mux.Context).With().Str("driver", "mikrotik").Logger()
			storeChan := gctx.GetStoreFromContext(mux.Context)

			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second * 5))
				sequence := mux.Sequence()
				for {
					hdr := &mikrotikRouterOS_Frame{}
					err := struc.Unpack(conn, hdr)
					if err != nil {
						fmt.Printf("err %+v\n", err)
						return
					}
					// repack the header... [TODO] this better
					var buf bytes.Buffer
					struc.Pack(&buf, hdr)

					// save session data
					hash := StoreHash(buf.Bytes(), storeChan)
					s.logger.Debug().Int("sequence", sequence).Str("phash", hash).Msg("Mikrotik RouterOS")
				}
			}(conn)
		}
	}
}

type mikrotikRouterOS_Frame struct {
	Length  uint8 `struc:"sizeof=Payload"`
	Payload []byte
	End     uint8
}
