// Package conman implements connection management
package conman

import (
	"context"
	"crypto/tls"
	"log/syslog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/antihax/gambit/internal/conman/config"
	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/conman/security"
	"github.com/antihax/gambit/internal/drivers"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/antihax/gambit/pkg/trie"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	fake "github.com/brianvoe/gofakeit/v6"
	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/rs/zerolog"
)

// ConnectionManager manages listeners
type ConnectionManager struct {
	tcpListeners map[uint16]net.Listener
	udpListeners map[uint16]net.Listener
	doneCh       chan struct{}
	tcpRules     *trie.Trie[muxconn.Proxy]
	udpRules     *trie.Trie[muxconn.Proxy]
	banners      map[uint16][]byte
	addresses    []net.IP

	// if we are saving raw entries, keep a list to save hitting fs
	knownHashes sync.Map

	banList *security.BanManager

	tcpmu sync.Mutex
	udpmu sync.Mutex

	// root logger
	logger zerolog.Logger

	// configurations
	config     *config.Config
	tlsConfig  tls.Config
	dtlsConfig dtls.Config

	uploader  *s3manager.Uploader
	storeChan chan store.File
}

// NewConMan creates a new ConnectionManager
func NewConMan() (*ConnectionManager, error) {

	// load config
	cfg, err := config.New(context.Background())
	if err != nil {
		return nil, err
	}

	if cfg.Profile {
		go runPProf()
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

	// setup the cipher suites
	suites := []uint16{}
	for _, cipher := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, cipher.ID)
	}

	// setup the conman
	s := &ConnectionManager{
		tcpListeners: make(map[uint16]net.Listener),
		udpListeners: make(map[uint16]net.Listener),
		doneCh:       make(chan struct{}),
		tcpRules:     trie.NewTrie[muxconn.Proxy](),
		udpRules:     trie.NewTrie[muxconn.Proxy](),
		banList:      security.NewBanManager(cfg.BanCount),
		banners:      make(map[uint16][]byte),
		logger:       logger,
		config:       cfg,
		tlsConfig: tls.Config{
			//lint:ignore SA1019 we know; that's the point.
			MinVersion:   tls.VersionSSL30,
			CipherSuites: suites,
		},
		dtlsConfig: dtls.Config{
			InsecureHashes: true,
			ServerName:     fake.DomainName(),
			ConnectContextMaker: func() (context.Context, func()) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
		},
	}

	// setup fake TLS
	fakeTLSCert, err := s.fakeTLSCertificate()
	if err != nil {
		return nil, err
	}
	s.tlsConfig.Certificates = []tls.Certificate{*fakeTLSCert}

	fakeDTLSCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	s.dtlsConfig.Certificates = []tls.Certificate{fakeDTLSCert}

	// setup any storage from config
	if err := s.setupStore(); err != nil {
		return nil, err
	}

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

	// Get our bind address
	gctx.IPAddress = s.listenAddress()

	// find all the TCP drivers and setup multiplexers
	driverList := drivers.GetDrivers()
	for _, d := range driverList {
		// start listeners for tcp handlers
		if handler, ok := d.(drivers.TCPDriver); ok {
			conn := muxconn.NewProxy(100)
			go handler.ServeTCP(conn)
			s.NewTCPDriver(d.Patterns(), conn)
		}

		if handler, ok := d.(drivers.UDPDriver); ok {
			conn := muxconn.NewProxy(100)
			go handler.ServeUDP(conn)
			s.NewUDPDriver(d.Patterns(), conn)
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

// NewTCPDriver adds a TCP driver to ConMan
func (s *ConnectionManager) NewTCPDriver(rules [][]byte, driver muxconn.Proxy) {
	for _, rule := range rules {
		s.tcpRules.Insert(rule, driver)
	}
}

// NewUDPDriver adds a UDP driver to ConMan
func (s *ConnectionManager) NewUDPDriver(rules [][]byte, driver muxconn.Proxy) {
	for _, rule := range rules {
		s.udpRules.Insert(rule, driver)
	}
}

// sendBanner tries to hint to an attacker what the port hosts if nothing was sent
func (s *ConnectionManager) sendBanner(ctx context.Context, muc *muxconn.MuxConn, port uint16) {
	time.Sleep(time.Second * time.Duration(s.config.BannerDelay))
	select {
	case <-ctx.Done(): // exit out
		return
	default: // send the banner if one exists
		if banner, ok := s.banners[port]; ok {
			if _, err := muc.Write(banner); err != nil {
				gctx.GetGlobalFromContext(muc.Context, "").Logger.Debug().Err(err).Msg("Sent Banner")
			}
		}
	}
}

// timeoutConnection prevents connectings lingering
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

// preloadTCPListeners gets an early start on a list of ports
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

// StartConning starts conman after configuration is completed
func (s *ConnectionManager) StartConning() {
	s.preloadTCPListeners()
	s.banList.Start()
	s.tcpManager()
	s.udpManager()
	for range s.doneCh {
		return
	}
}
