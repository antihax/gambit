package conman

// ConnectionManagerConfig
type ConnectionManagerConfig struct {
	SyslogAddress string `env:"CONMAN_SYSLOG_ADDRESS"`
	SyslogNetwork string `env:"CONMAN_SYSLOG_NETWORK"`
	LogLevel      int    `env:"CONMAN_LOGLEVEL,default=1"`
	Preload       uint16 `env:"CONMAN_LOGLEVEL,default=10000"`
	BannerDelay   int    `env:"CONMAN_BANNER_DELAY,default=3"`
	KillDelay     int    `env:"CONMAN_KILL_DELAY,default=10"`
	OutputFolder  string `env:"CONMAN_OUT_FOLDER"`
	S3Region      string `env:"CONMAN_S3_REGION"`
	S3Endpoint    string `env:"CONMAN_S3_ENDPOINT"`
	S3Bucket      string `env:"CONMAN_S3_BUCKET"`
	S3Key         string `env:"CONMAN_S3_KEY"`
	S3KeyID       string `env:"CONMAN_S3_KEYID"`
	Sanitize      bool   `env:"CONMAN_SANITIZE,default=1"`
	BindAddress   string `env:"CONMAN_BIND,default=public"`
}
