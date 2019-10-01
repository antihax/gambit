package driver

import "net"

// Driver implements a protocol handler
type Driver interface {
}

// TCPDriver handles TCP based aggressors after matching a sniff test
type TCPDriver interface {
	ServeTCP(ln net.Listener) error
}

// UDPDriver handles UDP based aggressors after matching a sniff test
type UDPDriver interface {
	ServeUDP(conn net.Conn) error
}

// TCPBannerDriver provide optional information to send if an aggressor does not
// do anything after connecting.
type TCPBannerDriver interface {
	// Banner returns a list of ports and byte string to return after a period
	// of inactivity in order to to coax a response.
	Banner() ([]uint16, []byte)
}
