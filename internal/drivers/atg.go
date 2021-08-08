package drivers

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"strconv"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	fake "github.com/brianvoe/gofakeit/v6"
	"github.com/rs/zerolog"
)

func init() {

	AddDriver(&atg{})
}

type atg struct {
	logger zerolog.Logger
}

func (s *atg) Patterns() [][]byte {
	return [][]byte{
		[]byte("I20100"),
	}
}

func (s *atg) ServeTCP(ln net.Listener) error {

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return err
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {
			s.logger = gctx.GetLoggerFromContext(mux.Context).With().Str("driver", "atg").Logger()
			storeChan := gctx.GetStoreFromContext(mux.Context)

			address := fake.Address()

			conn.Write([]byte(fmt.Sprintf(`
I20100
%s

%s
%s
%s,%s %s
%s

IN-TANK INVENTORY

TANK PRODUCT               VOLUME TC-VOLUME   ULLAGE   HEIGHT    WATER    TEMP
  1  Premium                 2348         0     4526    36.67     2.00   86.56
  2  Regular                 4231         0     5703    58.32     0.00   85.78
  3  Diesel                  5914         0     4870    33.58     0.23   88.73`,
				time.Now().Format("Jan 2, 2006 15:04"),
				fake.Company(),
				address.Street,
				address.City, fake.StateAbr(), address.Zip,
				fake.Phone(),
			)))

			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				tp := textproto.NewReader(reader)
				for {

					conn.SetDeadline(time.Now().Add(time.Second * 5))
					b, err := tp.ReadLineBytes()
					if err != nil {
						s.logger.Trace().Err(err).Msg("failed")
						return
					}
					sequence := mux.Sequence()
					s.logger.Warn().Int("sequence", sequence).Msg("atg knock")
					storeChan <- store.File{
						Filename: mux.GetUUID() + "-" + strconv.Itoa(sequence),
						Location: "sessions",
						Data:     b,
					}
				}
			}(conn)
		}
	}
}
