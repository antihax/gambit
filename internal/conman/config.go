package conman

// ConnectionManagerConfig reads configuration from environment variables
type ConnectionManagerConfig struct {
	SyslogAddress string   `env:"CONMAN_SYSLOG_ADDRESS"`
	SyslogNetwork string   `env:"CONMAN_SYSLOG_NETWORK"`
	LogLevel      int      `env:"CONMAN_LOGLEVEL,default=1"`
	Preload       uint16   `env:"CONMAN_PRELOAD,default=10000"`
	MaxPort       uint16   `env:"CONMAN_MAXPORT,default=45000"`
	IgnorePorts   []uint16 `env:"CONMAN_IGNORE_PORTS"`
	BanCount      int      `env:"CONMAN_BAN_COUNT,default=50"`
	BannerDelay   int      `env:"CONMAN_BANNER_DELAY,default=3"`
	KillDelay     int      `env:"CONMAN_KILL_DELAY,default=10"`
	OutputFolder  string   `env:"CONMAN_OUT_FOLDER"`
	S3Region      string   `env:"CONMAN_S3_REGION"`
	S3Endpoint    string   `env:"CONMAN_S3_ENDPOINT"`
	S3Bucket      string   `env:"CONMAN_S3_BUCKET"`
	S3Key         string   `env:"CONMAN_S3_KEY"`
	S3KeyID       string   `env:"CONMAN_S3_KEYID"`
	Sanitize      bool     `env:"CONMAN_SANITIZE,default=1"`
	BindAddress   string   `env:"CONMAN_BIND,default=public"`
}

// portIgnored returns true if the port is configured to be ignored, such as for ephemeral ports
func (s *ConnectionManagerConfig) portIgnored(port uint16) bool {
	if port > s.MaxPort {
		return true
	}
	for _, a := range s.IgnorePorts {
		if a == port {
			return true
		}
	}
	return false
}

// listenAddress determines the configured bind address for attackers
func (s *ConnectionManager) listenAddress() string {
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
	// short circuit next scan
	s.config.BindAddress = address
	return address
}
