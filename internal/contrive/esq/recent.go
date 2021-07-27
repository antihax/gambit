package esq

import (
	"encoding/json"
)

func (e *ESQ) Recent() ([]GambitFrame, error) {
	hits, err := e.Search(
		map[string]interface{}{
			"fields": []interface{}{
				map[string]interface{}{"field": "@timestamp", "format": "strict_date_optional_time"},
				"gambit.*",
			},
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{"range": map[string]interface{}{"@timestamp": map[string]interface{}{"gte": "now-1h", "format": "strict_date_optional_time"}}},
						map[string]interface{}{"exists": map[string]interface{}{"field": "gambit.hash"}},
					},
				},
			},
		}, 1000)
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

func (e *ESQ) RecentWS() ([]GambitFrame, error) {
	hits, err := e.Search(
		map[string]interface{}{
			"fields": []interface{}{
				map[string]interface{}{"field": "@timestamp", "format": "strict_date_optional_time"},
				"gambit.*",
			},
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						map[string]interface{}{"range": map[string]interface{}{"@timestamp": map[string]interface{}{"gte": "now-5s", "format": "strict_date_optional_time"}}},
						map[string]interface{}{"exists": map[string]interface{}{"field": "gambit.hash"}},
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
