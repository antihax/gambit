// Package security provides functionalities to manage security-related tasks such as banning IP addresses.
package security

import (
	"sync"
	"time"
)

// BanManager is a struct that manages a list of banned IP addresses and their ban status.
// It uses a sync.Map to store the last known addresses and a timeout duration for the ban period.
type BanManager struct {
	lastAddress sync.Map
	banCount    int
}

// NewBanManager creates a new BanManager
func NewBanManager(banCount int) *BanManager {
	return &BanManager{
		banCount: banCount,
	}
}

// clearBanlist removes all entries in the banlist
func (s *BanManager) clearBanlist() {
	s.lastAddress.Range(func(key interface{}, value interface{}) bool {
		s.lastAddress.Delete(key)
		return true
	})
}

// TickBanCounter increases the count on an IP list to prep for a ban
func (s *BanManager) TickBanCounter(ipAddress string) bool {
	var c int
	count, ok := s.lastAddress.Load(ipAddress)
	if ok {
		if count.(int) > s.banCount {
			return true
		}
		c = count.(int)
		c++
	}
	s.lastAddress.Store(ipAddress, c)

	return false
}

// Start ticks the banlist managers
func (s *BanManager) Start() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			<-ticker.C
			s.clearBanlist()
		}
	}()
}
