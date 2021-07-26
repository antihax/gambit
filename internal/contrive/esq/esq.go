package esq

import (
	"crypto/tls"
	"net/http"

	elastic "github.com/elastic/go-elasticsearch/v7"
)

type ESQ struct {
	es *elastic.Client
}

// NewESQ provides ElasticSearch queries
func NewESQ(address, user, pass string) (*ESQ, error) {
	es, err := elastic.NewClient(
		elastic.Config{
			Addresses: []string{
				address,
			},
			Username: user,
			Password: pass,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}
	esq := &ESQ{es: es}
	if ok, err := esq.Ping(); !ok || err != nil {
		return nil, err
	}

	return esq, nil
}

func (e *ESQ) Ping() (bool, error) {
	// ping to make sure we actually setup a connection
	_, err := e.es.Ping()
	if err != nil {
		return false, err
	}
	return true, nil
}
