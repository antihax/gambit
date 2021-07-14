package conman

// ConnectionManagerConfig
type ConnectionManagerConfig struct {
	SyslogAddress string `env:"CONMAN_SYSLOG_ADDRESS"`
	SyslogNetwork string `env:"CONMAN_SYSLOG_NETWORK"`
	LogLevel      int    `env:"CONMAN_LOGLEVEL,default=1"`
	BannerDelay   int    `env:"CONMAN_BANNER_DELAY,default=3"`
	KillDelay     int    `env:"CONMAN_KILL_DELAY,default=10"`
	OutputFolder  string `env:"CONMAN_OUT_FOLDER"`
	S3Host        string `env:"CONMAN_S3_HOST"`
	S3Bucket      string `env:"CONMAN_S3_BUCKET"`
	S3Key         string `env:"CONMAN_S3_KEY"`
}
