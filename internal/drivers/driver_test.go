package drivers

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Both UDP and TCP Struct
type Both struct{}

func (s *Both) ServeTCP(ln net.Listener) error {
	return nil
}

func (s *Both) ServeUDP(conn net.Conn) error {
	return nil
}

func (s *Both) Banner() ([]uint16, []byte) {
	return nil, nil
}

func (s *Both) Patterns() [][]byte {
	return nil
}

// UDP Struct
type UDP struct{}

func (s *UDP) Patterns() [][]byte {
	return nil
}

func (s *UDP) ServeUDP(conn net.Conn) error {
	return nil
}

// TCP Struct
type TCP struct{}

func (s *TCP) ServeTCP(ln net.Listener) error {
	return nil
}

func (s *TCP) Patterns() [][]byte {
	return nil
}

// Test an interface with both UDP and TCP is correct
func doBothInterface(t *testing.T, handle Driver) {
	udp, ok := handle.(UDPDriver)
	if assert.True(t, ok) {
		_, err := udp.ServeUDP(nil)
		assert.Nil(t, err)
	}
	tcp, ok := handle.(TCPDriver)
	if assert.True(t, ok) {
		assert.Nil(t, tcp.ServeTCP(nil))
	}
	tcpB, ok := handle.(TCPBannerDriver)
	if assert.True(t, ok) {
		tcpB.Banner()
	}
}

// Test an interface with just UDP is correct
func doUDPInterface(t *testing.T, handle Driver) {
	udp, ok := handle.(UDPDriver)
	if assert.True(t, ok) {
		_, err := udp.ServeUDP(nil)
		assert.Nil(t, err)
	}
	_, ok = handle.(TCPDriver)
	assert.False(t, ok)
}

// Test an interface with just TCP is correct
func doTCPInterface(t *testing.T, handle Driver) {
	// No UDP
	_, ok := handle.(UDPDriver)
	assert.False(t, ok)

	// Only TCP
	tcp, ok := handle.(TCPDriver)
	if assert.True(t, ok) {

		assert.Nil(t, tcp.ServeTCP(nil))
	}
}

func TestInterface(t *testing.T) {
	doBothInterface(t, &Both{})
	doTCPInterface(t, &TCP{})
	doUDPInterface(t, &UDP{})
}
