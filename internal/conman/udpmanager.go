package conman

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/drivers"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/lunixbochs/struc"
	"github.com/pion/udp"
)

// UDPHeader is the header for the UDP packets
type UDPHeader struct {
	Source      uint16
	Destination uint16
	Length      uint16
	Checksum    uint16
}

// udpManager listens for unknown packets and fires up listeners to handle
// in the future
func (s *ConnectionManager) udpManager() {
	conn, err := net.ListenIP("ip4:udp", nil)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			// read max MTU if available
			buf := make([]byte, 1500)
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				s.logger.Trace().Err(err).
					Str("network", "udp").
					Str("address", addr.String()).
					Msg("reading socket")
			}

			reader := bytes.NewReader(buf)
			header := UDPHeader{}

			struc.Unpack(reader, &header)
			if s.config.PortIgnored(header.Destination) {
				continue
			}
			// see if we match a rule and transfer the connection to the driver

			// fire up listener, kernel will take over future requests.
			known, err := s.CreateUDPListener(header.Destination)
			if err != nil {
				s.logger.Trace().Err(err).Msg("creating socket")
			}
			if !known {
				s.logger.Trace().Msgf("started udp server: %v", header.Destination)
			}

		}
	}()
}

// CreateUDPListener will create a new listener if one does not already exist and return if it was created or not.
func (s *ConnectionManager) CreateUDPListener(port uint16) (bool, error) {
	if port > s.config.MaxPort {
		return false, errors.New("above config.Maxport")
	}

	// create a new listener if one does not already exist
	s.udpmu.Lock()
	defer s.udpmu.Unlock()
	if _, ok := s.udpListeners[port]; !ok {
		addr := &net.UDPAddr{IP: net.ParseIP(gctx.IPAddress), Port: int(port)}
		ln, err := udp.Listen("udp", addr)
		if err != nil {
			return true, err
		}
		s.udpListeners[port] = ln

		// handle the connections
		go func() {
			var wg sync.WaitGroup
			for {
				conn, err := ln.Accept()
				if err == nil {
					wg.Add(1)
					go s.handleDatagram(conn, ln, &wg)
				}
			}
			wg.Wait()
		}()

		return false, nil
	}

	return true, nil
}

func (s *ConnectionManager) handleDatagram(conn net.Conn, root net.Listener, wg *sync.WaitGroup) {
	defer wg.Done()
	// ban hammers
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		if s.banList.TickBanCounter(addr.IP.String()) {
			conn.Close()
			return
		}
	}

	// create our sniffer
	ctx, globalutils := s.getGlobalContext()
	muc, err := muxconn.NewMuxConn(ctx, conn)
	if err != nil {
		s.logger.Debug().Str("network", "udp").Err(err).Msg("error building NewMuxConn")
		return
	}

	r := muc.StartSniffing()
	port := strconv.Itoa(root.Addr().(*net.UDPAddr).Port)
	ip := conn.RemoteAddr().(*net.UDPAddr).IP.String()

	timeoutCtx, timeoutCancel := context.WithCancel(context.Background())
	go s.timeoutConnection(timeoutCtx, muc)

	// How are those first bytes tasting?
	n := 1500
	buf := make([]byte, n)
	n, err = r.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.logger.Trace().Err(err).
				Str("network", "udp").
				Msg("error reading from sniffer")
			muc.Close()
		}
	}
	timeoutCancel() // Cancel the timeout

	tlsUnwrap := false
	// try unwrapping DTLS
	if buf[0] == 0x16 {
		muc.DoneSniffing()
		newMuxConn, newBuf, newN, err := s.decryptConn(ctx, muc, "udp")
		if err == nil {
			muc = newMuxConn
			buf = newBuf
			n = newN
			tlsUnwrap = true
		}
	}

	muc.SetDeadline(time.Now().Add(time.Second * 5))
	muc.Reset()
	// get the hash of the first n bytes and tag the context
	hash := drivers.GetHash(buf[:n])
	globalutils.MuxConn = muc
	globalutils.BaseHash = hash
	globalutils.Logger = globalutils.Logger.With().
		Bool("tlsunwrap", tlsUnwrap).
		Str("network", "udp").
		Str("attacker", ip).
		Str("uuid", muc.GetUUID()).
		Str("dstport", port).
		Str("hash", hash).
		Logger()

	// log the connection
	globalutils.Logger.Trace().Msgf("udp knock")

	// save the raw data
	if n > 0 {
		if _, ok := s.knownHashes.Load(hash); !ok {
			s.storeChan <- store.File{Filename: hash, Location: "raw", Data: buf[:n]}
		}
	}

	// see if we match a rule and transfer the connection to the driver
	ln, found := s.udpRules.Match(buf)

	// stop sniffing and pass to the driver listener
	muc.Reset()
	if found {
		// pipe the connection into Accept()
		ln.InjectConn(muc)
	} else {
		// no driver
		if n > 0 {
			globalutils.Logger.Debug().Err(err).Msg("no driver")
		}

		// close the connection
		muc.Close()
	}
}
