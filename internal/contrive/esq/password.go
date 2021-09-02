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

func (e *ESQ) PasswordList() ([]GambitFrame, error) {
	hits, _, err := e.SearchStr(`
	{
		"fields":[
		   {
			  "field":"@timestamp"
		   },
		   "gambit.attacker",
		   "gambit.driver",
		   "gambit.dstport",
		   "gambit.password",
		   "gambit.user"
		],
		"query":{
		   "bool":{
			  "filter":[
				 {
					"range":{
					   "@timestamp":{
						  "format":"strict_date_optional_time",
						  "gte":"now-30d"
					   }
					}
				 },
				 {
					"exists":{
					   "field":"gambit.password"
					}
				 }
			  ]
		   }
		}
	 }
	`, 10000)
	if err != nil {
		return nil, err
	}
	data := []GambitFrame{}
	if len(hits) > 0 {
		for _, hit := range hits {
			frame := GambitFrame{}
			if err := json.Unmarshal(*hit, &frame); err != nil {
				return nil, err
			}
			data = append(data, frame)
		}
	}
	return data, nil
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
