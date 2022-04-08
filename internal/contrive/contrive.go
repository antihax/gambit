package contrive

import (
	"context"

	"github.com/antihax/gambit/internal/contrive/esq"
	"github.com/sethvargo/go-envconfig"
)

// Contrive is the main service
type Contrive struct {
	ESQ           *esq.ESQ
	recentClients []chan []byte
	RootContext   context.Context
	Config        Config
}

// NewContrive creates a new contrive service
func NewContrive() (*Contrive, error) {
	// load config
	cfg := Config{}
	if err := envconfig.Process(context.Background(), &cfg); err != nil {
		return nil, err
	}

	// setup elastic connection
	esq, err := esq.NewESQ(cfg.ElasticAddress, cfg.ElasticUser, cfg.ElasticPass)
	if err != nil {
		return nil, err
	}

	// ping to make sure we actually setup a connection
	_, err = esq.Ping()
	if err != nil {
		return nil, err
	}

	c := &Contrive{
		ESQ:         esq,
		RootContext: context.Background(),
		Config:      cfg,
	}

	// start recent pump
	go c.recentPump()

	return c, nil
}

// Close the service
func (s *Contrive) Close() {

}
