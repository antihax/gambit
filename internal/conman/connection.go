package conman

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/pkg/muxconn"

	"github.com/antihax/gambit/internal/drivers"
	"github.com/antihax/gambit/internal/store"
	"github.com/pion/udp"
	"github.com/rs/zerolog"
)

// handleConnection handles both TCP and UDP with a common flow
func (s *ConnectionManager) handleConnection(conn net.Conn, listener net.Listener, wg *sync.WaitGroup, network string) {
	defer wg.Done()

	// Step 1: Validate connection (ban checks etc.)
	if !s.validateConnection(conn, network) {
		return
	}

	// Step 2: Initialize connection
	ctx, globalUtils := s.getGlobalContext()
	muc, port, ip, err := s.initializeConnection(ctx, conn, listener, network)
	if err != nil {
		s.logger.Debug().Str("network", network).Err(err).Msg("connection initialization failed")
		return
	}

	// Step 3: Detect protocol
	portNum, _ := strconv.ParseUint(port, 10, 16)
	muc, buf, n, cryptoUnwrapped, err := s.detectProtocol(ctx, muc, uint16(portNum), network)
	if err != nil && err != io.EOF {
		s.logger.Trace().Err(err).Str("network", network).Msg("protocol detection failed")
		muc.Close()
		return
	}

	// Step 4: Process connection data
	hash := s.processConnectionData(globalUtils, muc, buf[:n], cryptoUnwrapped, ip, port, network)

	// Step 5: Route connection
	s.routeConnection(muc, buf[:n], hash, network, globalUtils.Logger)
}

// validateConnection checks if the connection is allowed
func (s *ConnectionManager) validateConnection(conn net.Conn, network string) bool {
	if network == "tcp" {
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			if s.banList.TickBanCounter(addr.IP.String()) {
				conn.Close()
				return false
			}
		}
	} else { // UDP
		if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			if s.banList.TickBanCounter(addr.IP.String()) {
				conn.Close()
				return false
			}
		}
	}
	return true
}

// initializeConnection sets up the MuxConn and extracts connection info
func (s *ConnectionManager) initializeConnection(ctx context.Context, conn net.Conn, root net.Listener, network string) (*muxconn.MuxConn, string, string, error) {
	muc, err := muxconn.NewMuxConn(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, "", "", err
	}

	var port string
	var ip string

	if network == "tcp" {
		port = strconv.Itoa(root.Addr().(*net.TCPAddr).Port)
		ip = conn.RemoteAddr().(*net.TCPAddr).IP.String()
	} else { // UDP
		port = strconv.Itoa(root.Addr().(*net.UDPAddr).Port)
		ip = conn.RemoteAddr().(*net.UDPAddr).IP.String()
	}

	return muc, port, ip, nil
}

// detectProtocol handles both TCP and UDP protocol detection
func (s *ConnectionManager) detectProtocol(ctx context.Context, muc *muxconn.MuxConn, port uint16, network string) (*muxconn.MuxConn, []byte, int, bool, error) {
	var bannerCtx context.Context
	var bannerCancel context.CancelFunc

	// Banner is only for TCP
	if network == "tcp" {
		bannerCtx, bannerCancel = context.WithCancel(context.Background())
		go s.sendBanner(bannerCtx, muc, port)
		defer func() {
			if bannerCancel != nil {
				bannerCancel()
			}
		}()
	}

	// Both need timeout
	timeoutCtx, timeoutCancel := context.WithCancel(context.Background())
	go s.timeoutConnection(timeoutCtx, muc)
	defer timeoutCancel()

	// Read initial data
	bufSize := 4096
	if network == "udp" {
		bufSize = 1500 // UDP MTU size
	}

	r := muc.StartSniffing()
	buf := make([]byte, bufSize)
	n, err := r.Read(buf)

	// Cancel banner if we received data and it's TCP
	if network == "tcp" && bannerCancel != nil {
		bannerCancel()
		bannerCancel = nil
	}

	// Check for TLS/DTLS
	cryptoUnwrapped := false
	if n > 0 && buf[0] == 0x16 { // Same for TLS and DTLS handshake
		muc.DoneSniffing()
		newMuxConn, newBuf, newN, err := s.decryptConn(ctx, muc, network)
		if err == nil {
			muc = newMuxConn
			buf = newBuf
			n = newN
			cryptoUnwrapped = true
		} else {
			muc.Reset()
		}
	} else {
		muc.DoneSniffing()
	}

	// Set deadline - slightly shorter for UDP
	timeout := 5 * time.Second
	if network == "udp" {
		timeout = 3 * time.Second
	}
	muc.SetDeadline(time.Now().Add(timeout))
	muc.Reset()

	return muc, buf, n, cryptoUnwrapped, err
}

// processConnectionData handles logging, hashing, and data storage
func (s *ConnectionManager) processConnectionData(
	globalutils *gctx.GlobalUtils,
	muc *muxconn.MuxConn,
	data []byte,
	cryptoUnwrapped bool,
	ip, port, network string,
) string {
	hash := drivers.GetHash(data)

	// Update context
	globalutils.MuxConn = muc
	globalutils.BaseHash = hash

	// Append network-specific fields
	logger := globalutils.Logger.With().
		Bool("tlsunwrap", cryptoUnwrapped).
		Str("network", network).
		Str("attacker", ip).
		Str("uuid", muc.GetUUID()).
		Str("dstport", port).
		Str("hash", hash).
		Logger()

	globalutils.Logger = logger
	logger.Trace().Msgf("%s knock", network)

	// Store data if unique
	if len(data) > 0 {
		if _, ok := s.knownHashes.Load(hash); !ok {
			s.knownHashes.Store(hash, true)
			if s.storeChan != nil {
				s.storeChan <- store.File{Filename: hash, Location: "raw", Data: data}
			}
		}
	}

	return hash
}

// routeConnection handles finding and applying appropriate driver for both TCP and UDP
func (s *ConnectionManager) routeConnection(muc *muxconn.MuxConn, data []byte, hash string, network string, logger zerolog.Logger) {
	var driver muxconn.Proxy
	var found bool

	// Get appropriate rules based on network type
	if network == "tcp" {
		driver, found = s.tcpRules.Match(data)
	} else {
		driver, found = s.udpRules.Match(data)
	}

	if found {
		// Route to the driver
		driver.InjectConn(muc)
	} else {
		// No driver found
		if len(data) > 0 {
			logger.Debug().Str("network", network).Str("hash", hash).Msg("no driver found for connection")
		}
		muc.Close()
	}
}

// validatePort checks if a port should be ignored based on config
func (s *ConnectionManager) validatePort(port uint16) (bool, error) {
	if s.config.PortIgnored(port) {
		return false, fmt.Errorf("port %d is ignored", port)
	}
	return true, nil
}

// createListener is a generic function for creating both TCP and UDP listeners
func (s *ConnectionManager) createListener(port uint16, network string) (bool, error) {
	if valid, err := s.validatePort(port); !valid {
		return false, err
	}

	var listeners map[uint16]net.Listener
	var mu *sync.Mutex

	if network == "tcp" {
		listeners = s.tcpListeners
		mu = &s.tcpmu
	} else {
		listeners = s.udpListeners
		mu = &s.udpmu
	}

	mu.Lock()
	defer mu.Unlock()

	if _, ok := listeners[port]; ok {
		return true, nil // Already exists
	}

	if network == "tcp" {
		addr := fmt.Sprintf("%s:%d", s.listenAddress(), port)
		laddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return false, err
		}
		tcpLn, err := net.ListenTCP("tcp", laddr)
		if err != nil {
			return false, err
		}
		listeners[port] = tcpLn
	} else {
		addr := &net.UDPAddr{IP: net.ParseIP(gctx.IPAddress), Port: int(port)}
		ln, err := udp.Listen("udp", addr)
		if err != nil {
			return false, err
		}
		listeners[port] = ln
	}

	// Start handling connections
	go s.acceptConnections(listeners[port], network)

	return false, nil
}

// acceptConnections handles incoming connections for both TCP and UDP
func (s *ConnectionManager) acceptConnections(ln net.Listener, network string) {
	var wg sync.WaitGroup

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break // Listener was closed
			}
			s.logger.Debug().Err(err).Msg("accept error")
			continue
		}

		wg.Add(1)
		if network == "tcp" {
			go s.handleTCPConnection(conn, ln, &wg)
		} else {
			go s.handleUDPDatagram(conn, ln, &wg)
		}
	}

	wg.Wait()
}

func (s *ConnectionManager) CreateTCPListener(port uint16) (bool, error) {
	if valid, err := s.validatePort(port); !valid {
		return false, err
	}
	return s.createListener(port, "tcp")
}

// Then use with specific handlers:
func (s *ConnectionManager) handleTCPConnection(conn net.Conn, listener net.Listener, wg *sync.WaitGroup) {
	s.handleConnection(conn, listener, wg, "tcp")
}

func (s *ConnectionManager) handleUDPDatagram(conn net.Conn, listener net.Listener, wg *sync.WaitGroup) {
	s.handleConnection(conn, listener, wg, "udp")
}
