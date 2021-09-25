package drivers

import (
	"bufio"
	"log"
	"net"
	"strings"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/rs/zerolog"
	"github.com/secmask/go-redisproto"
)

type redis struct {
	logger zerolog.Logger
}

func init() {
	s := &redis{}
	AddDriver(s)
}

func (s *redis) Patterns() [][]byte {
	return [][]byte{
		{0x2A, 0x31, 0x0D, 0x0A, 0x24},
		{0x2A, 0x32, 0x0D, 0x0A, 0x24},
	}
}

// [TODO] add fake command responses
func (s *redis) ServeTCP(ln net.Listener) {

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("failed accept")
		}
		if mux, ok := c.(*muxconn.MuxConn); ok {
			s.logger = gctx.GetGlobalFromContext(mux.Context).Logger.With().Str("driver", "redis").Logger()
			storeChan := gctx.GetGlobalFromContext(mux.Context).Store

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				parser := redisproto.NewParser(conn)
				writer := redisproto.NewWriter(bufio.NewWriter(conn))
				for {
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					sequence := conn.Sequence()
					command, err := parser.ReadCommand()
					if err != nil {
						_, ok := err.(*redisproto.ProtocolError)
						if ok {
							writer.WriteError(err.Error())
							s.logger.Trace().Err(err).Msg("failed decoding")
							return
						}
						return
					} else {
						cmd := strings.ToUpper(string(command.Get(0)))
						s.logger.Info().Str("cmd", cmd).Int("sequence", sequence).Msg("redis command")
						switch cmd {
						case "AUTH":
							s.logger.Warn().Str("password", string(command.Get(1))).Int("sequence", sequence).Msg("tried password")
						default:
							writer.WriteBulkString("OK")
						}
					}
					if command.IsLast() {
						writer.Flush()
					}

					hash := StoreHash(conn.Snapshot(), storeChan)
					s.logger.Warn().Int("sequence", sequence).Str("phash", hash).Msg("redis knock")
				}
			}(mux)
		}
	}
}
