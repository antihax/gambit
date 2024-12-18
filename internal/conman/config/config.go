package config

import (
	"context"

	"github.com/sethvargo/go-envconfig"
)

// Config represents the configuration structure for the connection manager service.
// It handles environment-based configuration.
type Config struct {
	// SyslogAddress (CONMAN_SYSLOG_ADDRESS) specifies the address for syslog output
	SyslogAddress string `env:"CONMAN_SYSLOG_ADDRESS"`

	// SyslogNetwork (CONMAN_SYSLOG_NETWORK) defines the network type for syslog, defaults to "stdout"
	SyslogNetwork string `env:"CONMAN_SYSLOG_NETWORK,default=stdout"`

	// LogLevel (CONMAN_LOGLEVEL) sets the logging verbosity level, default is 1
	LogLevel int `env:"CONMAN_LOGLEVEL,default=1"`

	// Preload (CONMAN_PRELOAD) defines the number of ports to preload, default is 10000
	Preload uint16 `env:"CONMAN_PRELOAD,default=10000"`

	// MaxPort (CONMAN_MAXPORT) specifies the maximum port number to use, default is 45000
	MaxPort uint16 `env:"CONMAN_MAXPORT,default=45000"`

	// IgnorePorts (CONMAN_IGNORE_PORTS) lists ports to exclude from management
	IgnorePorts []uint16 `env:"CONMAN_IGNORE_PORTS"`

	// BanCount (CONMAN_BAN_COUNT) sets the threshold for banning connections, default is 50
	BanCount int `env:"CONMAN_BAN_COUNT,default=50"`

	// BannerDelay (CONMAN_BANNER_DELAY) defines the delay for banner display in seconds, default is 3
	BannerDelay int `env:"CONMAN_BANNER_DELAY,default=3"`

	// KillDelay (CONMAN_KILL_DELAY) sets the delay before killing connections in seconds, default is 10
	KillDelay int `env:"CONMAN_KILL_DELAY,default=10"`

	// OutputFolder (CONMAN_OUT_FOLDER) specifies the directory for output files
	OutputFolder string `env:"CONMAN_OUT_FOLDER"`

	// S3Region (CONMAN_S3_REGION) defines the AWS S3 region for storage
	S3Region string `env:"CONMAN_S3_REGION"`

	// S3Endpoint (CONMAN_S3_ENDPOINT) specifies the S3 endpoint URL
	S3Endpoint string `env:"CONMAN_S3_ENDPOINT"`

	// S3Bucket (CONMAN_S3_BUCKET) defines the S3 bucket name for storage
	S3Bucket string `env:"CONMAN_S3_BUCKET"`

	// S3Key (CONMAN_S3_KEY) provides the S3 secret key for authentication
	S3Key string `env:"CONMAN_S3_KEY"`

	// S3KeyID (CONMAN_S3_KEYID) provides the S3 key ID for authentication
	S3KeyID string `env:"CONMAN_S3_KEYID"`

	// Sanitize (CONMAN_SANITIZE) enables/disables output sanitization, default is true
	Sanitize bool `env:"CONMAN_SANITIZE,default=1"`

	// BindAddress (CONMAN_BIND) specifies the binding address, defaults to "public"
	BindAddress string `env:"CONMAN_BIND,default=public"`

	// Profile (CONMAN_PPROF) enables/disables profiling
	Profile bool `env:"CONMAN_PPROF"`

	ignoredPortsMap map[uint16]struct{}
}

// New creates a new instance of Config by processing environment variables.
func New(ctx context.Context) (*Config, error) {
	var c Config
	if err := envconfig.Process(ctx, &c); err != nil {
		return nil, err
	}

	// use a map for quicker lookups
	ignoredPortsMap := make(map[uint16]struct{}, len(c.IgnorePorts))
	for _, p := range c.IgnorePorts {
		ignoredPortsMap[p] = struct{}{}
	}

	return &c, nil
}

// PortIgnored returns true if the port is configured to be ignored, such as for ephemeral ports
func (c *Config) PortIgnored(port uint16) bool {
	_, ignored := c.ignoredPortsMap[port]
	return ignored
}
