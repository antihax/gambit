package conman

import "time"

// clearBanlist removes all entries in the banlist
func (s *ConnectionManager) clearBanlist() {
	s.lastAddress.Range(func(key interface{}, value interface{}) bool {
		s.lastAddress.Delete(key)
		return true
	})
}

// tickBan increases the count on an IP list to prep for a ban
func (s *ConnectionManager) tickBan(ipAddress string) bool {
	var c int
	count, ok := s.lastAddress.Load(ipAddress)
	if ok {
		if count.(int) > s.config.BanCount {
			return true
		}
		c = count.(int)
		c++
	}
	s.lastAddress.Store(ipAddress, c)

	return false
}

// banListManager ticks the banlist managers
func (s *ConnectionManager) banListManager() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			<-ticker.C
			s.clearBanlist()
		}
	}()
}
