// Package conman implements connection management
package conman

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/drivers"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/antihax/gambit/pkg/probe"
	"github.com/antihax/gambit/pkg/searchtree"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	fake "github.com/brianvoe/gofakeit/v6"
	"github.com/lunixbochs/struc"
	"github.com/rs/zerolog"
	"github.com/sethvargo/go-envconfig"
)

// ConnectionManager managers listeners
type ConnectionManager struct {
	tcpListeners map[uint16]net.Listener
	doneCh       chan struct{}
	tcpRules     searchtree.Tree
	udpRules     searchtree.Tree
	banners      map[uint16][]byte
	addresses    []net.IP

	// If we are saving raw entries, keep a list to save hitting fs
	knownHashes sync.Map
	lastAddress sync.Map
	logger      zerolog.Logger
	config      ConnectionManagerConfig
	tlsConfig   tls.Config
	uploader    *s3manager.Uploader
	storeChan   chan store.File
	RootContext context.Context
}

// NewConMan creates a new ConnectionManager
func NewConMan() (*ConnectionManager, error) {
	// load config
	cfg := ConnectionManagerConfig{}
	if err := envconfig.Process(context.Background(), &cfg); err != nil {
		return nil, err
	}

	// setup the logger
	logger := zerolog.New(os.Stdout)
	if cfg.SyslogNetwork != "stdout" {
		syslogWriter, err := syslog.Dial(cfg.SyslogNetwork, cfg.SyslogAddress, syslog.LOG_DAEMON, "conman")
		if err != nil {
			return nil, err
		}
		logger = zerolog.New(zerolog.SyslogCEEWriter(syslogWriter))
	}
	zerolog.SetGlobalLevel(zerolog.Level(cfg.LogLevel))

	suites := []uint16{}
	for _, cipher := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, cipher.ID)
	}

	// setup the conman
	s := &ConnectionManager{
		tcpListeners: make(map[uint16]net.Listener),
		doneCh:       make(chan struct{}),
		tcpRules:     searchtree.NewTree(),
		udpRules:     searchtree.NewTree(),
		banners:      make(map[uint16][]byte),
		logger:       logger,
		config:       cfg,
		tlsConfig: tls.Config{
			MinVersion:   tls.VersionSSL30,
			CipherSuites: suites,
		},
	}
	fakeCert, err := s.fakeTLSCertificate()
	if err != nil {
		return nil, err
	}
	s.tlsConfig.Certificates = []tls.Certificate{*fakeCert}

	// setup any storage from config
	if err := s.setupStore(); err != nil {
		return nil, err
	}

	// add logger and store to the global context
	s.RootContext = context.WithValue(context.Background(), gctx.LoggerContextKey, logger)
	s.RootContext = context.WithValue(s.RootContext, gctx.StoreContextKey, s.storeChan)

	// get a list of addresses
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if !privateIP(ip) {
				s.addresses = append(s.addresses, ip)
			}
		}
	}

	// find all the TCP drivers and setup multiplexers
	driverList := drivers.GetDrivers()
	for _, d := range driverList {
		// start listeners for tcp handlers
		if handler, ok := d.(drivers.TCPDriver); ok {
			conn := s.NewProxy()
			go handler.ServeTCP(conn)
			s.NewTCPDriver(d.Patterns(), conn.(muxconn.MuxListener))
		}

		if handler, ok := d.(drivers.UDPDriver); ok {
			s.NewUDPDriver(d.Patterns(), handler.ServeUDP)
		}

		// copy the banners to a map
		if handler, ok := d.(drivers.TCPBannerDriver); ok {
			if ports, banner := handler.Banner(); len(ports) > 0 {
				for _, port := range ports {
					s.banners[port] = banner
				}
			}
		}
	}
	return s, nil
}

// CreateTCPListener will create a new listener if one does not already exist and return if it was created or not.
func (s *ConnectionManager) CreateTCPListener(port uint16) (bool, error) {
	var wg sync.WaitGroup

	if port > s.config.MaxPort {
		return false, errors.New("above config.Maxport")
	}

	wg.Wait()

	address := "0.0.0.0"
	if s.config.BindAddress != "" {
		if s.config.BindAddress == "public" {
			for _, addr := range s.addresses {
				if !privateIP(addr) && addr.To4() != nil {
					address = addr.String()
				}
			}
		} else {
			address = s.config.BindAddress
		}
	}

	// create a new listener if one does not already exist
	if _, ok := s.tcpListeners[port]; !ok {
		addr := fmt.Sprintf("%s:%d", address, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return true, err
		}
		s.tcpListeners[port] = ln

		// handle the connections
		go func() {
			for {
				conn, err := ln.Accept()
				if err == nil {
					wg.Add(1)
					go s.handleConnection(conn, ln, &wg)
				}
			}
		}()

		return false, nil
	}

	return true, nil
}

// NewProxy provides a fake net.Listener
func (s *ConnectionManager) NewProxy() net.Listener {
	ml := muxconn.MuxListener{
		ConnCh: make(chan net.Conn, 40000),
	}
	return ml
}

// NewTCPDriver adds a driver to ConMan
func (s *ConnectionManager) NewTCPDriver(rules [][]byte, driver muxconn.MuxListener) {
	for _, rule := range rules {
		s.tcpRules.Insert(rule, driver)
	}
}

func (s *ConnectionManager) NewUDPDriver(rules [][]byte, driver drivers.UDPFunc) {
	for _, rule := range rules {
		s.udpRules.Insert(rule, driver)
	}
}

func (s *ConnectionManager) sendBanner(ctx context.Context, muc *muxconn.MuxConn, port uint16) {
	time.Sleep(time.Second * time.Duration(s.config.BannerDelay))
	select {
	case <-ctx.Done(): // exit out
		return
	default: // send the banner if one exists
		if banner, ok := s.banners[port]; ok {
			if _, err := muc.Write(banner); err != nil {
				log := gctx.GetLoggerFromContext(muc.Context)
				log.Debug().Err(err).Msg("Sent Banner")
			}
		}
	}
}

func (s *ConnectionManager) timeoutConnection(ctx context.Context, muc *muxconn.MuxConn) {
	time.Sleep(time.Second * time.Duration(s.config.KillDelay))
	select {
	case <-ctx.Done(): // exit out
		return
	default: // kill connections
		muc.Conn.Close()
		muc.Close()
	}
}

func (s *ConnectionManager) banListManager() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.clearBanlist()
			}
		}
	}()
}

func (s *ConnectionManager) preloadTCPListeners() {
	// prelisten everything
	if s.config.Preload > 0 {
		for i := uint16(1); i < s.config.Preload; i++ {
			_, err := s.CreateTCPListener(i)
			if err != nil {
				s.logger.Trace().Err(err).Msg("creating socket")
			}
		}
	}
}

func (s *ConnectionManager) tcpManager() {
	conn, _ := net.ListenIP("ip4:tcp", nil)
	go func() {
		for {
			// read max MTU if available
			buf := make([]byte, 1500)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil { // get out if we error
				s.logger.Trace().Err(err).
					Str("network", "tcp").
					Str("address", addr.String()).
					Msg("reading socket")
				continue
			}

			pkt := &probe.TCPPacket{}
			pkt.Decode(buf[:n])
			if pkt.Flags&probe.SYN != 0 {
				known, err := s.CreateTCPListener(pkt.DestPort)
				if err != nil {
					// Ignore the error because it just wont shut up
					s.logger.Trace().Err(err).Msg("creating socket")
				}
				if !known {
					s.logger.Trace().Msgf("started tcp server: %v", pkt.DestPort)
				}
			}
		}
	}()
}

type UDPHeader struct {
	Source      uint16
	Destination uint16
	Length      uint16
	Checksum    uint16
}

func (s *ConnectionManager) udpManager() {
	conn, err := net.ListenIP("ip4:udp", nil)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			// read max MTU if available
			buf := make([]byte, 1500)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}

			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if privateIP(ip) {
				continue
			}

			reader := bytes.NewReader(buf)
			header := UDPHeader{}

			struc.Unpack(reader, &header)
			if s.config.PortIgnored(header.Destination) {
				continue
			}
			// see if we match a rule and transfer the connection to the driver

			hash := drivers.StoreHash(buf[8:n], s.storeChan)

			attacklog := s.logger.With().
				Bool("tlsunwrap", false).
				Str("network", "udp").
				Str("attacker", ip.String()).
				Str("dstport", strconv.Itoa(int(header.Destination))).
				Str("hash", hash).Logger()

			entry := s.udpRules.Match(buf[8:n])
			if d, ok := entry.(drivers.UDPFunc); ok {
				_, err = d(buf[8:n])
				if err != nil {
					continue
				}
			}

			attacklog.Info().Msg("udp knock")
		}
	}()
}

func (s *ConnectionManager) StartConning() {
	s.preloadTCPListeners()
	s.banListManager()
	s.tcpManager()
	s.udpManager()
	for range s.doneCh {
		return
	}
}

func (s *ConnectionManager) fakeTLSCertificate() (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tml := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(25, 0, 0),
		SerialNumber: big.NewInt(fake.Int64()),
		Subject: pkix.Name{
			CommonName:   fake.DomainName(),
			Organization: []string{fake.Company()},
		},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func (s *ConnectionManager) unwrapTLS(conn net.Conn) (*muxconn.MuxConn, []byte, int, error) {
	n := 1500
	buf := make([]byte, n)
	tlsConn := tls.Server(conn, &s.tlsConfig)
	muc := muxconn.NewMuxConn(s.RootContext, tlsConn)
	r := muc.StartSniffing()
	n, err := r.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.logger.Debug().Str("network", "tcp").
				Err(err).Msg("error unwrapping tls")
			muc.DoneSniffing()
			return nil, nil, 0, err
		}
	}

	return muc, buf, n, err
}

func (s *ConnectionManager) clearBanlist() {
	s.lastAddress.Range(func(key interface{}, value interface{}) bool {
		s.lastAddress.Delete(key)
		return true
	})
}

func (s *ConnectionManager) handleConnection(conn net.Conn, root net.Listener, wg *sync.WaitGroup) {
	defer wg.Done()

	// Ban hammers
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		var c int
		count, ok := s.lastAddress.Load(addr.IP.String())
		if ok {
			if count.(int) > s.config.BanCount {
				conn.Close()
				return
			}
			c = count.(int)
			c++
		}
		s.lastAddress.Store(addr.IP.String(), c)
	}

	// create our sniffer
	muc := muxconn.NewMuxConn(s.RootContext, conn)
	r := muc.StartSniffing()
	port := strconv.Itoa(root.Addr().(*net.TCPAddr).Port)
	ip := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// fire a request to send a banner if the attacker does not send first
	bannerCtx, bannerCancel := context.WithCancel(context.Background())
	go s.sendBanner(bannerCtx, muc, uint16(root.Addr().(*net.TCPAddr).Port))

	timeoutCtx, timeoutCancel := context.WithCancel(context.Background())
	go s.timeoutConnection(timeoutCtx, muc)

	// How are those first bytes tasting?
	n := 1500
	buf := make([]byte, n)
	n, err := r.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.logger.Debug().Err(err).
				Str("network", "tcp").
				Msg("error reading from sniffer")
			muc.Close()
		}
	}
	bannerCancel()  // Cancel the banner
	timeoutCancel() // Cancel the timeout

	tlsUnwrap := false
	// Try unwrapping TLS/SSL
	if buf[0] == 0x16 {
		muc.DoneSniffing()
		newMuxConn, newBuf, newN, err := s.unwrapTLS(muc)
		if err == nil {
			muc = newMuxConn
			buf = newBuf
			n = newN
			tlsUnwrap = true
		}
	}

	// get the hash of the first n bytes and tag the context
	hash := drivers.GetHash(buf[:n])
	muc.Context = context.WithValue(muc.Context, gctx.HashContextKey, hash)

	// log the connection
	attacklog := gctx.GetLoggerFromContext(muc.Context).With().Bool("tlsunwrap", tlsUnwrap).Str("network", "tcp").Str("attacker", ip).Str("uuid", muc.GetUUID()).Str("dstport", port).Str("hash", hash).Logger()
	muc.Context = context.WithValue(muc.Context, gctx.LoggerContextKey, attacklog)
	attacklog.Trace().Msgf("tcp knock")

	// save the raw data
	if n > 0 {
		if _, ok := s.knownHashes.Load(hash); !ok {
			s.storeChan <- store.File{Filename: hash, Location: "raw", Data: buf[:n]}
		}
	}

	// see if we match a rule and transfer the connection to the driver
	entry := s.tcpRules.Match(buf)

	// stop sniffing and pass to the driver listener
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
			attacklog.Debug().Err(err).Msg("no driver")
		}

		// close the connection
		muc.Close()
	}
}
