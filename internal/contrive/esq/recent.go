package esq

import (
	"encoding/json"
)

func (e *ESQ) Recent() ([]GambitFrame, error) {
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
						  "gte":"now-8h"
					   }
					}
				 },
				 {
					"exists":{
					   "field":"gambit.hash"
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
	`, 5000)

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
							  "gte":"now-1s"
						   }
						}
					 },
					 {
						"exists":{
						   "field":"gambit.hash"
						}
					 }
				  ]
			   }
			}
		 }`, 100)
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
