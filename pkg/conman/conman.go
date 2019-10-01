// Package conman implements connection management
package conman

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/antihax/pass/internal/drivers"
	"github.com/antihax/pass/pkg/driver"
	"github.com/antihax/pass/pkg/muxconn"
	"github.com/antihax/pass/pkg/searchtree"
)

// ConnectionManager managers listeners
type ConnectionManager struct {
	tcpListeners map[uint16]net.Listener
	doneCh       chan struct{}
	rules        searchtree.Tree
}

// NewConMan creates a new ConnectionManager
func NewConMan() *ConnectionManager {
	s := &ConnectionManager{
		tcpListeners: make(map[uint16]net.Listener),
		doneCh:       make(chan struct{}),
		rules:        searchtree.NewTree(),
	}

	// Find all the TCP drivers and setup multiplexers
	drivers := drivers.GetDrivers()
	for _, d := range drivers {
		driver, ok := d.Driver.(driver.TCPDriver)
		if ok {
			conn := s.NewProxy()
			go driver.ServeTCP(conn)
			s.NewTCPDriver(d.Pattern, conn.(muxconn.MuxListener))
		}
	}
	return s
}

// CreateTCPListener will create a new listener if one does not already exist and return if it was created or not.
func (s *ConnectionManager) CreateTCPListener(port uint16) (bool, error) {
	var wg sync.WaitGroup
	wg.Wait()

	// create a new listener if one does not already exist
	if _, ok := s.tcpListeners[port]; !ok {
		addr := fmt.Sprintf("0.0.0.0:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return true, err
		}
		s.tcpListeners[port] = ln

		go func() {
			for {
				conn, _ := ln.Accept()
				wg.Add(1)
				go s.handleConnection(conn, ln, &wg)
			}
		}()

		return false, nil
	}

	return true, nil
}

// NewProxy provides a new fake net.Listener
func (s *ConnectionManager) NewProxy() net.Listener {
	ml := muxconn.MuxListener{
		ConnCh: make(chan net.Conn, 1500),
	}
	return ml
}

// NewTCPDriver adds a driver to ConMan
func (s *ConnectionManager) NewTCPDriver(rule []byte, driver muxconn.MuxListener) {
	s.rules.Insert(rule, driver)
}

func (s *ConnectionManager) handleConnection(conn net.Conn, root net.Listener, wg *sync.WaitGroup) {
	// create our sniffer
	muc := muxconn.NewMuxConn(conn)

	defer func() {
		wg.Done()
	}()

	// Waiter: How are those first bytes tasting?
	r := muc.StartSniffing()
	buf := make([]byte, 1500)
	n, err := r.Read(buf)
	if err != nil {
		if err != io.EOF {
			fmt.Println("read error:", err)
		}
	}

	// See if we match a rule and transfer the connection to the driver
	entry := s.rules.Match(buf)
	muc.DoneSniffing()
	ln, ok := entry.(muxconn.MuxListener)
	if ok {
		// Hack in the source listener
		ln.Listener = root
		// Pipe the connection into Accept()
		ln.ConnCh <- muc
	}
	if n > 10 {
		n = 10
	}
	fmt.Printf("---------------\n%s\n%X\n", buf, buf[:n])

}
