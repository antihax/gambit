package conman

func (s *ConnectionManager) clearBanlist() {
	s.lastAddress.Range(func(key interface{}, value interface{}) bool {
		s.lastAddress.Delete(key)
		return true
	})
}

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
