package esq

import (
	"encoding/json"
)

func (e *ESQ) SessionsForHash(hash string) ([]GambitFrame, error) {
	hits, _, err := e.Search(
		map[string]interface{}{
			"sort": []interface{}{
				map[string]interface{}{"@timestamp": map[string]interface{}{"order": "desc", "unmapped_type": "boolean"}},
			},
			"fields": []interface{}{
				map[string]interface{}{"field": "@timestamp", "format": "strict_date_optional_time"},
				"gambit.*",
			},
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{"range": map[string]interface{}{"@timestamp": map[string]interface{}{"gte": "now-30d", "format": "strict_date_optional_time"}}},
						map[string]interface{}{"match_phrase": map[string]interface{}{"gambit.hash": hash}},
						map[string]interface{}{"exists": map[string]interface{}{"field": "gambit.sequence"}},
					},
				},
			},
		}, 100)
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
