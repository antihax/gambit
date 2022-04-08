package drivers

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	fake "github.com/brianvoe/gofakeit/v6"
)

func init() {
	AddDriver(&atg{})
}

type atg struct {
}

func (s *atg) Patterns() [][]byte {
	return [][]byte{
		[]byte("I20100"),
	}
}

func (s *atg) ServeTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return
		}

		if mux, ok := conn.(*muxconn.MuxConn); ok {
			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				glob := gctx.GetGlobalFromContext(conn.Context, "atg")

				address := fake.Address()

				conn.Write([]byte(fmt.Sprintf(banner,
					time.Now().Format("Jan 2, 2006 15:04"),
					fake.Company(),
					address.Street,
					address.City, fake.StateAbr(), address.Zip,
					fake.Phone(),
				)))

				reader := bufio.NewReader(conn)
				tp := textproto.NewReader(reader)
				for {
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					_, err := tp.ReadLineBytes()
					if err != nil {
						glob.Logger.Trace().Err(err).Msg("failed")
						return
					}

					glob.NewSession(conn.Sequence(), StoreHash(conn.Snapshot(), glob.Store)).
						ATTACKICSPointTagIdentification(gctx.Value{Key: "tag", Value: "I20100"})
				}
			}(mux)
		}
	}
}

var banner = `
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
  3  Diesel                  5914         0     4870    33.58     0.23   88.73`
