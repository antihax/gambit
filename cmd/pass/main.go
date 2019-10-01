package main

import (
	"log"
	"net"

	"github.com/antihax/pass/pkg/conman"
	"github.com/antihax/pass/pkg/probe"
)

func main() {
	conn, _ := net.ListenIP("ip4:tcp", nil)
	conman := conman.NewConMan()

	for {
		buf := make([]byte, 1500)
		n, addr, _ := conn.ReadFrom(buf)
		pkt := &probe.TCPPacket{}
		pkt.Decode(buf[:n])
		if pkt.Flags&probe.SYN != 0 {
			known, err := conman.CreateTCPListener(pkt.DestPort)
			if err != nil {
				log.Println(err)
			}
			if !known {
				log.Printf("started tcp server: %v", pkt.DestPort)
			}
			log.Printf("tcp knock: %v:%v", addr, pkt.DestPort)
		}
	}
}
