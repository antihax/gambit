package drivers

import (
	"fmt"
	"net"

	"github.com/aprice/telnet"
)

func init() {
	serv := telnet.NewServer(":9999", telnet.HandleFunc(func(c *telnet.Connection) {
		fmt.Println("hi")
		c.Write([]byte("Hello world!\r\n"))
		c.Close()
	}))
	s := &telnetServer{Server: serv}
	AddDriver(s)
}

type telnetServer struct {
	Server *telnet.Server
}

func (s *telnetServer) Patterns() [][]byte {
	return [][]byte{
		{0x0D, 0x0A},
	}
}

func (s *telnetServer) ServeTCP(ln net.Listener) {
	go s.Server.Serve(ln)
}
