package contrive

type ContriveConfig struct {
	ElasticAddress string `env:"CONTRIVE_ELASTIC_ADDRESS"`
	ElasticUser    string `env:"CONTRIVE_ELASTIC_USER"`
	ElasticPass    string `env:"CONTRIVE_ELASTIC_PASS"`
}
