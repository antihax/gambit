package esq

import (
	"encoding/json"
)

type Unknowns struct {
	User struct {
		Buckets []struct {
			Key      string `json:"key"`
			DocCount int    `json:"doc_count"`
		} `json:"buckets"`
	} `json:"user"`
}

func (e *ESQ) Unknowns() (*Unknowns, error) {
	_, agg, err := e.SearchStr(`
	{
		"aggs": {
			"user": {
				"terms": {
					"field": "gambit.hash.keyword",
					"order": {
						"_count": "desc"
					},
					"size": 1000
				}
			}
		},
		"fields": [
		],
		"size": 0,
		"query": {
			"bool": {
				"filter": [
					{
						"range": {
							"@timestamp": {
								"gte": "now-30d",
								"format": "strict_date_optional_time"
							}
						}
					},
				 {
					"term":{
					   "gambit.message.keyword":"no driver"
					}
				 }
				]
			}
		}
	}
	`, 0)

	if err != nil {
		return nil, err
	}
	data := Unknowns{}

	if err := json.Unmarshal(*agg, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
