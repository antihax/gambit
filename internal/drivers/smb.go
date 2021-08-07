package drivers

import (
	"bytes"
	"log"
	"net"
	"unsafe"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/lunixbochs/struc"
	"github.com/rs/zerolog"
)

func init() {
	//xFF SMB
	AddDriver([]byte{255, 83, 77, 66}, &smb{})
}

type smb struct {
	logger zerolog.Logger
}

func (s *smb) ServeTCP(ln net.Listener) error {
	const (
		CommandNegotiate uint8 = iota + 114
		CommandSessionSetup
		CommandLogoff
		CommandTreeConnect
		CommandTreeDisconnect
		CommandCreate
		CommandClose
		CommandFlush
		CommandRead
		CommandWrite
		CommandLock
		CommandIOCtl
		CommandCancel
		CommandEcho
		CommandQueryDirectory
		CommandChangeNotify
		CommandQueryInfo
		CommandSetInfo
		CommandOplockBreak
	)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return err
		}
		if mux, ok := conn.(*muxconn.MuxConn); ok {
			s.logger = gctx.GetLoggerFromContext(mux.Context).With().Str("driver", "sshd").Logger()
		}
		go func(conn net.Conn) {
			defer conn.Close()
			for {
				var size uint32
				hdr := &smb_HeaderV1{}

				// Get the whole message
				struc.Unpack(conn, &size)
				b := make([]byte, size)
				struc.Unpack(conn, &b)

				buf := bytes.NewReader(b)

				// Get the header
				struc.Unpack(buf, hdr)

				switch hdr.Command {
				case CommandNegotiate:
					r := &smb_NegotiateRespV1{
						SecurityMode:    0x2,
						DialectRevision: 0x0202,
					}
					r.Command = CommandNegotiate

					struc.Pack(conn, uint32(unsafe.Sizeof(r)))
					struc.Pack(conn, r)

				case CommandSessionSetup:
					r := &smb_NegotiateRespV1{}
					r.Command = CommandSessionSetup
					struc.Pack(conn, uint32(unsafe.Sizeof(r)))
					struc.Pack(conn, r)

				case CommandTreeConnect:
					r := &smb_NegotiateRespV1{}
					r.Command = CommandTreeConnect
					struc.Pack(conn, uint32(unsafe.Sizeof(r)))
					struc.Pack(conn, r)
				default: // Byeeeeeeeeeeeee
					return
				}
			}
		}(conn)
	}
}

/*func bread(b io.Reader, v interface{}) error {
	return binary.Read(b, binary.BigEndian, v)
}*/

type smb_HeaderV1 struct {
	ProtocolID       [4]uint8
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures uint64
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

type smb_NegotiateRespV1 struct {
	smb_HeaderV1
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	Reserved             uint16
	ServerGuid           [16]byte
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16 `struc:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `struc:"len:SecurityBlob"`
	Reserved2            uint32
	SecurityBlob         []byte
}
