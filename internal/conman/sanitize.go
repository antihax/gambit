package conman

import (
	"bytes"
	"net"
	"strings"
)

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

// Sanitize makes a dumb attempt to remove our addresses from data. It won't catch them all.
func (s *ConnectionManager) Sanitize(data []byte) []byte {
	if s.config.Sanitize {
		for _, ip := range s.addresses {
			data = bytes.ReplaceAll(data, ip, bytes.Repeat([]byte{255}, len(ip)))
			data = []byte(strings.ReplaceAll(string(data), ip.String(), "xxx.xxx.xxx.xxx"))
		}
	}
	return data
}
