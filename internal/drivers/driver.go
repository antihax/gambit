package drivers

import "net"

var drivers []Driver

// [TODO] this will need to change for sequencing..
type UDPFunc func(data []byte) ([]byte, error)

// AddDriver adds a driver to the internal list
func AddDriver(handler Driver) {
	drivers = append(drivers, handler)
}

// GetDrivers returns the available driver list
func GetDrivers() []Driver {
	return drivers
}

// Driver implements a protocol handler
type Driver interface {
	Patterns() [][]byte
}

// TCPDriver handles TCP based aggressors after matching a sniff test
type TCPDriver interface {
	ServeTCP(ln net.Listener) error
}

// UDPDriver handles UDP based aggressors after matching a sniff test
type UDPDriver interface {
	ServeUDP([]byte) ([]byte, error)
}

// TCPBannerDriver provide optional information to send if an aggressor does not
// do anything after connecting.
type TCPBannerDriver interface {
	// Banner returns a byte string to return after a period
	// of inactivity in order to to coax a response.
	Banner() ([]uint16, []byte)
}
