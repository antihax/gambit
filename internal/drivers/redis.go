package drivers

import (
	"bufio"
	"log"
	"net"
	"strings"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/secmask/go-redisproto"
)

type redis struct {
	INFO string
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

func (s *redis) out(sr string) string {
	return strings.Replace(sr, "\n", "\r\r\n", -1)
}

func (s *redis) flattenCommand(c *redisproto.Command) (r string) {
	for i := 0; i < c.ArgCount(); i++ {
		r += string(c.Get(i)) + " "
	}
	r = strings.TrimSpace(r)
	return r
}

// [TODO] add fake command responses
func (s *redis) ServeTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("failed accept")
		}
		if mux, ok := c.(*muxconn.MuxConn); ok {
			glob := gctx.GetGlobalFromContext(mux.Context, "redis")

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()

				parser := redisproto.NewParser(conn)
				writer := redisproto.NewWriter(bufio.NewWriter(conn))
				for {
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					command, err := parser.ReadCommand()
					if err != nil {
						writer.WriteError(err.Error())
						glob.LogError(err)
						return
					}

					cmd := strings.ToUpper(string(command.Get(0)))
					l := glob.NewSession(conn.Sequence(), StoreHash(conn.Snapshot(), glob.Store))
					l.AppendLogger(
						gctx.Value{Key: "opCode", Value: cmd},
						gctx.Value{Key: "args", Value: s.flattenCommand(command)},
					)
					l.Logger.Info().Msg("redis knock")
					if err != nil {
						_, ok := err.(*redisproto.ProtocolError)
						if ok {
							writer.WriteError(err.Error())
							glob.LogError(err)
							return
						}
						glob.LogError(err)
						return
					} else {
						l.ATTACKEntActiveScanning()
						switch cmd {
						case "AUTH":
							l.ATTACKEntPasswordGuessing(
								gctx.Value{Key: "user", Value: "redis"},
								gctx.Value{Key: "pass", Value: string(command.Get(1))},
							)
							writer.WriteBulkString("OK")
						case "CLIENT":
							switch strings.ToUpper(string(command.Get(1))) {
							case "LIST":
								writer.WriteBulkString(s.out(REDIS_CLIENT_LIST))
							default:
								writer.WriteBulkString("OK")
							}

						case "CONFIG":
							switch strings.ToUpper(string(command.Get(1))) {
							case "SET":
								if string(command.Get(3)) == "crontab" || string(command.Get(3)) == "/etc/cron.d/" {
									l.ATTACKEntCron()
								} else {
									l.ATTACKEntDataManipulation()
								}
								writer.WriteBulkString("OK")
							default:
								writer.WriteBulkString("OK")
							}
						case "FLUSHALL":
							l.ATTACKEntDataDestruction()
						case "PING":
							writer.WriteBulkString("PONG")
						case "INFO":
							writer.WriteBulkString(s.out(REDIS_INFO))
						case "COMMAND":
							writer.WriteBulkString(REDIS_COMMAND)
						case "NONEXISTENT":
							writer.WriteError("ERR unknown command `NONEXISTENT`, with args beginning with:")
						default:
							writer.WriteBulkString("OK")
						}
					}
					if command.IsLast() {
						writer.Flush()
					}
				}
			}(mux)
		}
	}
}
