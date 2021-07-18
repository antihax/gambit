// Package conman implements connection management
package conman

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/antihax/pass/internal/drivers"
	"github.com/antihax/pass/pkg/driver"
	"github.com/antihax/pass/pkg/muxconn"

	"github.com/antihax/pass/pkg/probe"
	"github.com/antihax/pass/pkg/searchtree"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/rs/zerolog"
	"github.com/sethvargo/go-envconfig"
)

// ConnectionManager managers listeners
type ConnectionManager struct {
	tcpListeners map[uint16]net.Listener
	doneCh       chan struct{}
	rules        searchtree.Tree
	banners      map[uint16][]byte
	addresses    []net.IP

	// If we are saving raw entries, keep a list to save hitting fs
	knownHashes sync.Map
	logger      zerolog.Logger
	config      ConnectionManagerConfig
	uploader    *s3manager.Uploader
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

	// setup the conman
	s := &ConnectionManager{
		tcpListeners: make(map[uint16]net.Listener),
		doneCh:       make(chan struct{}),
		rules:        searchtree.NewTree(),
		banners:      make(map[uint16][]byte),
		logger:       logger,
		config:       cfg,
	}

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

	// find all the TCP drivers and setup multiplexers
	drivers := drivers.GetDrivers()
	for _, d := range drivers {
		// start listeners for tcp handlers
		if handler, ok := d.Driver.(driver.TCPDriver); ok {
			conn := s.NewProxy()
			go handler.ServeTCP(conn)
			s.NewTCPDriver(d.Pattern, conn.(muxconn.MuxListener))
		}

		// copy the banners to a map
		if handler, ok := d.Driver.(driver.TCPBannerDriver); ok {
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

// NewProxy provides a fake net.Listener
func (s *ConnectionManager) NewProxy() net.Listener {
	ml := muxconn.MuxListener{
		ConnCh: make(chan net.Conn, 1500),
		Logger: s.logger,
	}
	return ml
}

// NewTCPDriver adds a driver to ConMan
func (s *ConnectionManager) NewTCPDriver(rule []byte, driver muxconn.MuxListener) {
	s.rules.Insert(rule, driver)
}

func (s *ConnectionManager) sendBanner(ctx context.Context, muc *muxconn.MuxConn, port uint16) {
	time.Sleep(time.Second * time.Duration(s.config.BannerDelay))
	select {
	case <-ctx.Done(): // exit out
		return
	default: // send the banner if one exists
		if banner, ok := s.banners[port]; ok {
			if _, err := muc.Write(banner); err != nil {
				log := muc.GetLogger()
				log.Debug().Err(err).Msg("")
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

func (s *ConnectionManager) StartConning() {
	conn, _ := net.ListenIP("ip4:tcp", nil)
	// prelisten everything
	if s.config.Preload > 0 {
		for i := uint16(1); i < s.config.Preload; i++ {
			_, err := s.CreateTCPListener(i)
			if err != nil {
				s.logger.Debug().Err(err).Msg("creating socket")
			}
		}
	}

	for {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil { // get out if we error
			s.logger.Debug().Err(err).
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
				s.logger.Debug().Msgf("started tcp server: %v", pkt.DestPort)
			}
		}
	}
}

func (s *ConnectionManager) handleConnection(conn net.Conn, root net.Listener, wg *sync.WaitGroup) {
	defer wg.Done()

	// create our sniffer
	muc := muxconn.NewMuxConn(conn, s.logger)
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
			s.logger.Debug().Err(err).Msg("error reading from sniffer")
			muc.Close()
		}
	}
	bannerCancel()  // Cancel the banner
	timeoutCancel() // Cancel the timeout

	// get the hash of the first n bytes and tag the multiplexer
	h := sha1.New()
	h.Write(buf[:n])
	muc.SetHash(hex.EncodeToString(h.Sum(nil)))

	// log the connection
	attacklog := muc.GetLogger()
	attacklog.Info().Str("attacker", ip).Str("dstport", port).Msgf("tcp knock")

	// save the raw data [TODO] from config
	if n > 0 {
		if _, ok := s.knownHashes.Load(muc.GetHash()); !ok {
			s.Store(muc.GetHash(), "raw", buf[:n])
			s.knownHashes.Store(muc.GetHash(), false)
		}
	}

	// see if we match a rule and transfer the connection to the driver
	entry := s.rules.Match(buf)

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
			attacklog.Debug().Err(err).Str("dstport", port).Str("raw", string(buf[:n])).Msg("no driver")
		}

		// close the connection
		muc.Close()
	}
}
