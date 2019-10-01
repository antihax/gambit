package drivers

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"unsafe"

	"github.com/lunixbochs/struc"
)

func init() {
	//xFF SMB
	AddDriver([]byte{255, 83, 77, 66}, &smb{})
}

type smb struct {

}

func (s *smb) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("failed to accept %s\n", err)
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			for {
				var size uint32
				hdr := &HeaderV1{}

				// Get the whole message
				struc.Unpack(conn, &size)
				b := make([]byte, size)
				struc.Unpack(conn, &b)

				buf := bytes.NewReader(b)

				// Get the header
				struc.Unpack(buf, hdr)

				switch hdr.Command {
				case CommandNegotiate:
					r := &NegotiateRespV1{
						SecurityMode:    0x2,
						DialectRevision: 0x0202,
					}
					r.Command = CommandNegotiate

					struc.Pack(conn, uint32(unsafe.Sizeof(r)))
					struc.Pack(conn, r)

				case CommandSessionSetup:
					r := &NegotiateRespV1{}
					r.Command = CommandSessionSetup
					struc.Pack(conn, uint32(unsafe.Sizeof(r)))
					struc.Pack(conn, r)

				case CommandTreeConnect:
					r := &NegotiateRespV1{}
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

func bread(b io.Reader, v interface{}) error {
	return binary.Read(b, binary.BigEndian, v)
}

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

type HeaderV1 struct {
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

type NegotiateRespV1 struct {
	HeaderV1
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