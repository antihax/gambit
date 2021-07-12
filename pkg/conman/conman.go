// Package conman implements connection management
package conman

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"sync"

	"github.com/antihax/pass/internal/drivers"
	"github.com/antihax/pass/pkg/driver"
	"github.com/antihax/pass/pkg/muxconn"
	"github.com/antihax/pass/pkg/searchtree"
	"github.com/rs/zerolog/log"
)

// ConnectionManager managers listeners
type ConnectionManager struct {
	tcpListeners map[uint16]net.Listener
	doneCh       chan struct{}
	rules        searchtree.Tree

	// If we are saving raw entries, keep a list to save hitting fs
	knownHashes map[string]bool
}

// NewConMan creates a new ConnectionManager
func NewConMan() *ConnectionManager {
	s := &ConnectionManager{
		tcpListeners: make(map[uint16]net.Listener),
		doneCh:       make(chan struct{}),
		rules:        searchtree.NewTree(),
		knownHashes:  make(map[string]bool),
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
	n := 1500
	buf := make([]byte, n)

	// [TODO] timeout and send banner
	n, err := r.Read(buf)
	if err != nil {
		if err != io.EOF {
			log.Error().Err(err).Msg("error reading from sniffer")
		}
	}

	// get the hash of the first n bytes and tag the multiplexer
	h := sha1.New()
	h.Write(buf[:n])
	muc.SetHash(hex.EncodeToString(h.Sum(nil)))

	port := strconv.Itoa(root.Addr().(*net.TCPAddr).Port)
	ip := root.Addr().(*net.TCPAddr).IP.String()

	// log the connection
	attacklog := muc.GetLogger()
	attacklog.Info().Str("attacker", ip).Str("dstport", port).Msgf("tcp knock")

	// save the raw data [TODO] from config
	if _, ok := s.knownHashes[muc.GetHash()]; !ok {
		if err = ioutil.WriteFile("./raw/"+muc.GetHash(), buf[:n], 0644); err != nil {
			log.Error().Err(err).Msg("error saving raw data")
		}
		s.knownHashes[muc.GetHash()] = false
	}

	// see if we match a rule and transfer the connection to the driver
	entry := s.rules.Match(buf)

	muc.DoneSniffing()
	ln, ok := entry.(muxconn.MuxListener)
	if ok {
		// hack in the source listener
		ln.Listener = root
		// pipe the connection into Accept()
		ln.ConnCh <- muc
	} else {
		// no driver
		if n > 0 {
			attacklog.Debug().Err(err).Str("dstport", port).Str("raw", string(buf[:n])).Msg("no driver")
		}
	}
}
