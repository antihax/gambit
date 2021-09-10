package drivers

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/lunixbochs/struc"
	"github.com/rs/zerolog"
)

func init() {

	AddDriver(&rdp{})
}

// [TODO] this may be too aggressive
func (s *rdp) Patterns() [][]byte {
	return [][]byte{
		{3, 0, 0},
	}
}

type rdp struct {
	logger zerolog.Logger
}

// [TODO] Refactor this cluster or find an actual library to do it
type rdp_CONNECTIONCONFIRM struct {
	Version   uint8
	Reserved  uint8
	Size      uint16
	Length    uint8
	Code      uint8
	DstRef    uint16
	SrcRef    uint16
	Class     uint8
	Type      uint8
	Flags     uint8
	Length2   uint16 `struct:"little"`
	Protocols uint32 `struct:"little"`
}

type rdp_TPKTHeader struct {
	Version  uint8
	Reserved uint8
	Size     uint16
}

type rdp_TPDU struct {
	Length uint8
	Code   uint8
}

type rdp_X224 struct {
	DstRef uint16
	SrcRef uint16
	Class  uint8
}

type rdp_X224CRQ struct {
	rdp_X224
	Cookie []byte `struc:"[0]byte"`
}

type rdp_NEGREQ struct {
	Type      uint8
	Flags     uint8
	Length    uint16 `struct:"little"`
	Protocols uint32 `struct:"little"`
}

// UnwrapTPKT reads the TPKT header and payload
func (s *rdp) UnwrapTPKT(conn net.Conn) (*rdp_TPKTHeader, []byte, error) {
	hdr := &rdp_TPKTHeader{}
	if err := struc.Unpack(conn, hdr); err != nil {
		return nil, nil, err
	}
	if hdr.Size < 4 || hdr.Size > 500 {
		fmt.Printf("%+v\n", hdr)
		return nil, nil, errors.New("wrong payload size")
	}
	if hdr.Version != 3 {
		return nil, nil, errors.New("unknown version")
	}
	b := make([]byte, hdr.Size-4)

	if _, err := conn.Read(b); err != nil {
		return nil, nil, err
	}

	return hdr, b, nil
}

// UnwrapTPDU reads the PDU header and payload
func (s *rdp) UnwrapTPDUHeader(reader *bytes.Reader) (*rdp_TPDU, error) {
	pdu := &rdp_TPDU{}

	if err := struc.Unpack(reader, &pdu); err != nil {
		return nil, err
	}

	return pdu, nil
}

// Unwrap negotiation request
func (s *rdp) ReadNegotiationRequest(reader *bytes.Reader, size uint8) (*rdp_X224CRQ, *rdp_NEGREQ, error) {
	neg := &rdp_X224CRQ{}
	req := &rdp_NEGREQ{}
	if err := struc.Unpack(reader, &neg); err != nil {
		return nil, nil, err
	}

	// read cookie and req
	if size > 14 {
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return neg, nil, err
			}
			if b != 0x0d {
				neg.Cookie = append(neg.Cookie, b)
			} else { // at end
				reader.ReadByte() // Consume 0x0a byte
				break
			}
		}
	}
	if err := struc.Unpack(reader, &req); err != nil {
		return neg, req, err
	}
	return neg, req, nil
}

const (
	TPDU_CR = 0b1110 // Negotiation request
	TPDU_CC = 0b1101 // Negotiation confirm
	TPDU_DR = 0b1000 // Disconnect request
	TPDU_DT = 0b1111 // Data
)

func (s *rdp) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return err
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {

			s.logger = gctx.GetLoggerFromContext(mux.Context).With().Str("driver", "rdp").Logger()
			storeChan := gctx.GetStoreFromContext(mux.Context)

			go func(conn *muxconn.MuxConn) {
				defer conn.Close()
				for {
					conn.SetDeadline(time.Now().Add(time.Second * 5))
					sequence := mux.Sequence()

					hdr, b, err := s.UnwrapTPKT(conn)
					if err != nil {
						s.logger.Trace().Err(err).Msg("rdp knock")
						return
					}

					// save session data
					hash := StoreHash(conn.Snapshot(), storeChan)

					s.logger.Debug().Int("sequence", sequence).Str("phash", hash).Msg("rdp message")

					reader := bytes.NewReader(b)
					pdu, err := s.UnwrapTPDUHeader(reader)
					if err != nil {
						s.logger.Trace().Err(err).Int("sequence", sequence).Msg("rdp knock")
						return
					}
					switch pdu.Code >> 4 {
					case TPDU_CR:
						neg, req, err := s.ReadNegotiationRequest(reader, pdu.Length)
						if err != nil {
							s.logger.Trace().Err(err).Int("sequence", sequence).Msg("rdp knock")
							return
						}

						var buf bytes.Buffer
						if err := struc.Pack(&buf, &rdp_CONNECTIONCONFIRM{
							Version:   hdr.Version,
							Size:      0x13,
							Code:      0xd0,
							Length:    0x0e,
							SrcRef:    0x1234,
							Class:     neg.Class,
							Flags:     req.Flags,
							Type:      0x02,
							Length2:   0x08,
							Protocols: 0x00000000,
						}); err != nil {
							s.logger.Trace().Err(err).Int("sequence", sequence).Msg("rdp knock")
							return
						}
						conn.Write(buf.Bytes())
					default:
						fmt.Printf("\n%+v\n%+v\n\n", hdr, b)
					}
				}
			}(mux)
		}
	}
}
