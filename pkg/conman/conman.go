// Package conman implements connection management
package conman

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antihax/pass/internal/drivers"
	"github.com/antihax/pass/pkg/driver"
	"github.com/antihax/pass/pkg/muxconn"
	"github.com/antihax/pass/pkg/probe"
	"github.com/antihax/pass/pkg/searchtree"
	"github.com/rs/zerolog"
	"github.com/sethvargo/go-envconfig"
)

// ConnectionManager managers listeners
type ConnectionManager struct {
	tcpListeners      map[uint16]net.Listener
	doneCh            chan struct{}
	rules             searchtree.Tree
	banners           map[uint16][]byte
	sanitizeAddresses []net.IP

	// If we are saving raw entries, keep a list to save hitting fs
	knownHashes map[string]bool
	logger      zerolog.Logger
	config      ConnectionManagerConfig
}

// [TODO] Remove after golang 1.17 released
func privateIP(ip net.IP) bool {
	private := false
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return true
	}
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	private = private24BitBlock.Contains(ip) || private20BitBlock.Contains(ip) || private16BitBlock.Contains(ip)

	return private
}

// NewConMan creates a new ConnectionManager
func NewConMan() (*ConnectionManager, error) {
	// load config
	cfg := ConnectionManagerConfig{}
	if err := envconfig.Process(context.Background(), &cfg); err != nil {
		return nil, err
	}
	if cfg.OutputFolder == "" {
		if pw, err := os.Getwd(); err != nil {
			return nil, err
		} else {
			cfg.OutputFolder = pw + "/"
		}
	}
	os.Mkdir(cfg.OutputFolder+"raw", 0755)
	os.Mkdir(cfg.OutputFolder+"sessions", 0755)

	logger := zerolog.New(os.Stdout)
	if cfg.SyslogNetwork != "stdout" {
		syslogWriter, err := syslog.Dial(cfg.SyslogNetwork, cfg.SyslogAddress, syslog.LOG_DAEMON, "conman")
		if err != nil {
			return nil, err
		}
		//logger = zerolog.New(syslogWriter)
		logger = zerolog.New(zerolog.SyslogCEEWriter(syslogWriter))
	}
	zerolog.SetGlobalLevel(zerolog.Level(cfg.LogLevel))

	s := &ConnectionManager{
		tcpListeners: make(map[uint16]net.Listener),
		doneCh:       make(chan struct{}),
		rules:        searchtree.NewTree(),
		banners:      make(map[uint16][]byte),
		knownHashes:  make(map[string]bool),
		logger:       logger,
		config:       cfg,
	}

	// get a list of addresses to sanitize from exported data
	if cfg.Sanitize {
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
					s.sanitizeAddresses = append(s.sanitizeAddresses, ip)
				}
			}
		}
	}

	// Find all the TCP drivers and setup multiplexers
	drivers := drivers.GetDrivers()
	for _, d := range drivers {
		// start listeners for tcp handlers
		if handler, ok := d.Driver.(driver.TCPDriver); ok {
			conn := s.NewProxy()
			go handler.ServeTCP(conn)
			s.NewTCPDriver(d.Pattern, conn.(muxconn.MuxListener))
		}

		// Copy the banners to a map
		if handler, ok := d.Driver.(driver.TCPBannerDriver); ok {
			if driv, ok := handler.(driver.TCPBannerDriver); ok {
				if ports, banner := driv.Banner(); len(ports) > 0 {
					for _, port := range ports {
						s.banners[port] = banner
					}
				}
			}
		}
	}
	return s, nil
}

// Make some dumb attempt to remove our addresses from data. It won't catch them all.
func (s *ConnectionManager) Sanitize(data []byte) []byte {
	for _, ip := range s.sanitizeAddresses {
		data = bytes.ReplaceAll(data, ip, bytes.Repeat([]byte{255}, len(ip)))
		data = []byte(strings.ReplaceAll(string(data), ip.String(), "xxx.xxx.xxx.xxx"))
	}
	return data
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
	for i := uint16(1); i < 65535; i++ {
		_, err := s.CreateTCPListener(i)
		if err != nil {
			s.logger.Debug().Err(err).Msg("creating socket")
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
		if _, ok := s.knownHashes[muc.GetHash()]; !ok {
			if err = ioutil.WriteFile(s.config.OutputFolder+"raw/"+muc.GetHash(), s.Sanitize(buf[:n]), 0644); err != nil {
				s.logger.Debug().Err(err).Msg("error saving raw data")
			}
			s.knownHashes[muc.GetHash()] = false
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
