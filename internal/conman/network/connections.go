package network

import (
	"net"
	"sync"
)

type ConnectionManager interface {
	Start() error
	Stop()
	CreateListener(port uint16) (bool, error)
	handleConnection(conn net.Conn, root net.Listener, wg *sync.WaitGroup)
}
