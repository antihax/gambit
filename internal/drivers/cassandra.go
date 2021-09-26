package drivers

import (
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/datastax/go-cassandra-native-protocol/client"
	"github.com/datastax/go-cassandra-native-protocol/frame"
	"github.com/datastax/go-cassandra-native-protocol/message"
	"github.com/datastax/go-cassandra-native-protocol/primitive"
	"github.com/rs/zerolog"
)

type cassandra struct {
	logger zerolog.Logger
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
			glob := gctx.GetGlobalFromContext(mux.Context)
			glob.Logger = glob.Logger.With().Str("driver", "cassandra").Logger()

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				for {
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					sequence := conn.Sequence()
					in, err := codec.DecodeFrame(conn)
					if err != nil {
						s.logger.Trace().Err(err).Msg("failed")
						return
					}

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
							s.logger.Trace().Err(err).Msg("failed")
							return
						}

					case primitive.OpCodeStartup:
						frame := frame.NewFrame(in.Header.Version,
							in.Header.StreamId,
							&message.Authenticate{Authenticator: "org.apache.cassandra.auth.PasswordAuthenticator"})
						err := codec.EncodeFrame(frame, conn)
						if err != nil {
							s.logger.Trace().Err(err).Msg("failed")
							return
						}
					case primitive.OpCodeAuthResponse:
						if authResponse, ok := in.Body.Message.(*message.AuthResponse); !ok {
							s.logger.Trace().Err(err).Msg("failed decoding auth")
							return
						} else {
							cred := &client.AuthCredentials{}
							if err = cred.Unmarshal(authResponse.Token); err == nil {
								s.logger.Warn().Str("opcode", in.Header.OpCode.String()).Str("technique", "T1110").Str("user", cred.Username).Str("password", cred.Password).Int("sequence", sequence).Msg("tried password")
							}
						}

						authError := frame.NewFrame(in.Header.Version, in.Header.StreamId, &message.AuthenticationError{ErrorMessage: "invalid credentials"})
						err := codec.EncodeFrame(authError, conn)
						if err != nil {
							s.logger.Trace().Err(err).Msg("failed")
							return
						}
					}
					hash := StoreHash([]byte(in.String()), glob.Store)
					glob.Logger.Info().Str("opcode", in.Header.OpCode.String()).Int("sequence", sequence).Str("phash", hash).Msg("cassandra opCode")
				}
			}(mux)
		}
	}
}
