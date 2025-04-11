package drivers

import (
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/pkg/muxconn"
	"github.com/datastax/go-cassandra-native-protocol/client"
	"github.com/datastax/go-cassandra-native-protocol/frame"
	"github.com/datastax/go-cassandra-native-protocol/message"
	"github.com/datastax/go-cassandra-native-protocol/primitive"
)

type cassandra struct {
}

func init() {
	s := &cassandra{}
	AddDriver(s)
}

func (s *cassandra) Patterns() [][]byte {
	return [][]byte{
		{0x04, 0x00, 0x12, 0x34, 0x01},
		{0x42, 0x00, 0x00, 0x00, 0x05},
	}
}

func (s *cassandra) ServeTCP(ln net.Listener) {
	codec := frame.NewCodec()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("failed accept")
			return
		}
		if mux, ok := c.(*muxconn.MuxConn); ok {
			glob := gctx.GetGlobalFromContext(mux.Context, "cassandra")

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				for {
					conn.SetDeadline(time.Now().Add(time.Second * 5))

					in, err := codec.DecodeFrame(conn)
					if err != nil {
						glob.Logger.Trace().Err(err).Msg("failed")
						return
					}

					l := glob.NewSession(conn.Sequence(), StoreHash([]byte(in.String()), glob.Store))
					l.AppendLogger(gctx.Value{Key: "opCode", Value: in.Header.OpCode.String()})
					l.Logger.Info().Msg("cassandra opCode")

					switch in.Header.OpCode {
					case primitive.OpCodeOptions:
						frame := frame.NewFrame(in.Header.Version, in.Header.StreamId,
							&message.Supported{
								Options: map[string][]string{
									"CQL_VERSION": {"3.0.0"},
									"COMPRESSION": {},
								},
							},
						)

						err := codec.EncodeFrame(frame, conn)
						if err != nil {
							l.LogError(err)
							return
						}

					case primitive.OpCodeStartup:
						frame := frame.NewFrame(in.Header.Version,
							in.Header.StreamId,
							&message.Authenticate{Authenticator: "org.apache.cassandra.auth.PasswordAuthenticator"})
						err := codec.EncodeFrame(frame, conn)
						if err != nil {
							l.LogError(err)
							return
						}
					case primitive.OpCodeAuthResponse:
						if authResponse, ok := in.Body.Message.(*message.AuthResponse); !ok {
							l.LogError(err)
							return
						} else {
							cred := &client.AuthCredentials{}
							if err = cred.Unmarshal(authResponse.Token); err == nil {
								l.ATTACKEntPasswordGuessing(
									gctx.Value{Key: "user", Value: cred.Username},
									gctx.Value{Key: "pass", Value: cred.Password},
								)
							}
						}

						authError := frame.NewFrame(in.Header.Version, in.Header.StreamId, &message.AuthenticationError{ErrorMessage: "invalid credentials"})
						err := codec.EncodeFrame(authError, conn)
						if err != nil {
							l.LogError(err)
							return
						}
					}
				}
			}(mux)
		}
	}
}
