package esq

import (
	"encoding/json"
)

func (e *ESQ) SessionsForHash(hash string) ([]GambitFrame, error) {
	hits, _, err := e.SearchStr(`
	{
		"fields":[
		   {
			  "field":"@timestamp",
			  "format":"strict_date_optional_time"
		   },
		   "gambit.*"
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
					"match_phrase":{
					   "gambit.hash":"`+hash+`"
					}
				 },
				 {
					"exists":{
					   "field":"gambit.sequence"
					}
				 }
			  ]
		   }
		},
		"sort":[
		   {
			  "@timestamp":{
				 "order":"desc",
				 "unmapped_type":"boolean"
			  }
		   }
		]
	 }	
	`, 1000)
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

func (e *ESQ) HashsForSession(session string) ([]GambitFrame, error) {
	hits, _, err := e.SearchStr(`
	{
		"fields":[
		   {
			  "field":"@timestamp",
			  "format":"strict_date_optional_time"
		   },
		   "gambit.*"
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
					"match_phrase":{
					   "gambit.session":"`+session+`"
					}
				 },
				 {
					"exists":{
					   "field":"gambit.sequence"
					}
				 }
			  ]
		   }
		},
		"sort":[
		   {
			  "@timestamp":{
				 "order":"desc",
				 "unmapped_type":"boolean"
			  }
		   }
		]
	 }	
	`, 1000)
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
