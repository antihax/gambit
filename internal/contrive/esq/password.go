package esq

import (
	"encoding/json"
)

type RecentPasswords struct {
	User struct {
		Buckets []struct {
			Key      string `json:"key"`
			DocCount int    `json:"doc_count"`
			Pass     struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"pass"`
		} `json:"buckets"`
	} `json:"user"`
}

func (e *ESQ) RecentPasswords() (*RecentPasswords, error) {
	_, agg, err := e.SearchStr(`
	{
		"aggs": {
			"user": {
				"terms": {
					"field": "gambit.user.keyword",
					"order": {
						"_count": "desc"
					},
					"size": 100
				},
				"aggs": {
					"pass": {
						"terms": {
							"field": "gambit.password.keyword",
							"order": {
								"_count": "desc"
							},
							"size": 100
						}
					}
				}
			}
		},
		"fields": [
		],
		"query": {
			"bool": {
				"filter": [
					{
						"range": {
							"@timestamp": {
								"gte": "now-1y",
								"format": "strict_date_optional_time"
							}
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
	data := RecentPasswords{}

	if err := json.Unmarshal(*agg, &data); err != nil {
		return nil, err
	}

	return &data, nil
}
