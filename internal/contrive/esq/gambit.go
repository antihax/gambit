package esq

import "time"

type GambitFrame struct {
	Attacker  []string    `json:"gambit.attacker,omitempty"`
	Driver    []string    `json:"gambit.driver,omitempty"`
	Dstport   []string    `json:"gambit.dstport,omitempty"`
	Error     []string    `json:"gambit.error,omitempty"`
	Hash      []string    `json:"gambit.hash,omitempty"`
	PHash     []string    `json:"gambit.phash,omitempty"`
	Network   []string    `json:"gambit.network,omitempty"`
	Level     []string    `json:"gambit.level,omitempty"`
	Message   []string    `json:"gambit.message,omitempty"`
	TLSUnwrap []bool      `json:"gambit.tlsunwrap,omitempty"`
	Password  []string    `json:"gambit.password,omitempty"`
	Sequence  []int       `json:"gambit.sequence,omitempty"`
	Timestamp []time.Time `json:"@timestamp,omitempty"`
	URL       []string    `json:"gambit.url,omitempty"`
	UUID      []string    `json:"gambit.uuid,omitempty"`
	User      []string    `json:"gambit.user,omitempty"`
}
