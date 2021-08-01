package esq

import (
	"bytes"
	"encoding/json"
)

func (e *ESQ) Search(query map[string]interface{}, limit int) ([]*json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := e.es.Search(
		e.es.Search.WithIndex("filebeat*"),
		e.es.Search.WithBody(&buf),
		e.es.Search.WithSource("false"),
		e.es.Search.WithSize(limit),
	)

	if err != nil {
		return nil, err
	}

	var j ESHeader
	if err = json.NewDecoder(res.Body).Decode(&j); err != nil {
		res.Body.Close()
		return nil, err
	}
	res.Body.Close()
	data := []*json.RawMessage{}
	if j.Hits.Total.Value > 0 {
		for _, hit := range j.Hits.Hits {
			data = append(data, hit.Fields)
		}
	}
	return data, nil
}
