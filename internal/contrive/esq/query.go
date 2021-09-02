package esq

import (
	"bytes"
	"encoding/json"
	"strings"
)

func (e *ESQ) Search(query map[string]interface{}, limit int) ([]*json.RawMessage, *json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, nil, err
	}

	return e.SearchStr(buf.String(), limit)
}

func (e *ESQ) SearchStr(query string, limit int) ([]*json.RawMessage, *json.RawMessage, error) {
	res, err := e.es.Search(
		e.es.Search.WithIndex("filebeat*"),
		e.es.Search.WithBody(strings.NewReader(query)),
		e.es.Search.WithSort("@timestamp:desc"),
		e.es.Search.WithSource("false"),
		e.es.Search.WithSize(limit),
	)

	if err != nil {
		return nil, nil, err
	}

	var j ESHeader
	if err = json.NewDecoder(res.Body).Decode(&j); err != nil {
		res.Body.Close()
		return nil, nil, err
	}
	res.Body.Close()
	data := []*json.RawMessage{}
	if j.Hits.Total.Value > 0 {
		for _, hit := range j.Hits.Hits {
			data = append(data, hit.Fields)
		}
	}
	return data, j.Aggregations, nil
}
