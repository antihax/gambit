package drivers

import (
	"net"

	"github.com/miekg/dns"
)

func init() {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		panic(err)
	}
	AddDriver(&evildns{
		backHaul: udpConn,
	})
}

type evildns struct {
	server   *dns.Server
	backHaul *net.UDPConn
}

func (s *evildns) Patterns() [][]byte {
	return [][]byte{
		{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

func (s *evildns) ServeUDP(data []byte) ([]byte, error) {
	/*s.backHaul.Write(data)
	b := make([]byte, 1500)
	i, err := s.backHaul.Read(b)

	return b[:i], err*/
	return nil, nil
}

func (s *evildns) ServeTCP(ln net.Listener) error {
	dns.ActivateAndServe(ln, s.backHaul, nil)
	return nil
}
