package drivers

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func init() {
	s := &evildns{}
	AddDriver(s)
	dns.DefaultMsgAcceptFunc = s.MsgAcceptFunc
}

type evildns struct {
}

func (s *evildns) Patterns() [][]byte {
	return [][]byte{
		{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

func (s *evildns) ServeUDP(ln net.Listener) error {
	if err := dns.ActivateAndServe(ln, nil, dns.HandlerFunc(s.Handler)); err != nil {
		panic(err)
	}
	return nil
}

func (s *evildns) ServeTCP(ln net.Listener) error {
	if err := dns.ActivateAndServe(ln, nil, dns.HandlerFunc(s.Handler)); err != nil {
		panic(err)
	}
	return nil
}

func (s *evildns) Handler(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Printf("HANDLE %+v\n", r.String())
}

func (s *evildns) MsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	fmt.Printf("ACCEPT %+v\n", dh)
	return dns.MsgAccept
}
