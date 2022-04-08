package contrive

// Config is the configuration for the contrive service
type Config struct {
	ElasticAddress string `env:"CONTRIVE_ELASTIC_ADDRESS"`
	ElasticUser    string `env:"CONTRIVE_ELASTIC_USER"`
	ElasticPass    string `env:"CONTRIVE_ELASTIC_PASS"`
	BucketURL      string `env:"CONTRIVE_BUCKET_URL"`
}
