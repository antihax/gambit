// Package conman implements connection management
package conman

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/syslog"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/internal/drivers"
	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/antihax/gambit/pkg/searchtree"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	fake "github.com/brianvoe/gofakeit/v6"
	"github.com/rs/zerolog"
	"github.com/sethvargo/go-envconfig"
)

// ConnectionManager managers listeners
type ConnectionManager struct {
	tcpListeners map[uint16]net.Listener
	udpListeners map[uint16]net.Listener
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
		udpListeners: make(map[uint16]net.Listener),
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
			conn := s.NewProxy()
			go handler.ServeUDP(conn)
			s.NewUDPDriver(d.Patterns(), conn.(muxconn.MuxListener))
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

func (s *ConnectionManager) NewUDPDriver(rules [][]byte, driver muxconn.MuxListener) {
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
			muc.Reset()
			return nil, nil, 0, err
		}
	}

	return muc, buf, n, err
}
