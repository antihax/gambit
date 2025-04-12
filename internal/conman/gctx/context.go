// Package gctx provides glue for contexts used by conman
package gctx

import (
	"context"

	"github.com/antihax/gambit/internal/store"
	"github.com/antihax/gambit/pkg/muxconn"
	"github.com/rs/zerolog"
)

// contextKey for conman contexts
type contextKey struct {
	key string
}

var (
	// GlobalContextKey holds globalutils for drivers
	GlobalContextKey = &contextKey{"globalutils"}
	// IPAddress holds the bind address from the configuration to be shared with drivers
	IPAddress string
)

func NewGlobalContext(ctx context.Context, globals *GlobalUtils) context.Context {
	return context.WithValue(ctx, GlobalContextKey, globals)
}

// GlobalUtils provides utils for drivers
type GlobalUtils struct {
	MuxConn      *muxconn.MuxConn
	Logger       zerolog.Logger
	BaseHash     string
	Store        chan store.File
	DriverMarked bool
}

// GetGlobalFromContext returns store channel from conman context for saving raw packets
func GetGlobalFromContext(ctx context.Context, driver string) *GlobalUtils {
	c := ctx.Value(GlobalContextKey).(*GlobalUtils)
	// zerolog allows for multiple keys, but we only want to mark the driver once
	if driver != "" && !c.DriverMarked {
		c.Logger = c.Logger.With().Str("driver", driver).Logger()
		c.DriverMarked = true
	}
	return c
}

// AppendLogger adds the key/value to further log entries
func (g *GlobalUtils) AppendLogger(values ...Value) {
	for _, v := range values {
		g.Logger = g.Logger.With().Interface(v.Key, v.Value).Logger()
	}
}

func (g *GlobalUtils) LogError(e error) {
	g.Logger.Trace().
		Err(e).
		Msg("error")
}

func (g *GlobalUtils) NewSession(seqNum int, phash string) *Session {
	return &Session{
		Logger: g.Logger.With().
			Int("sequence", seqNum).
			Str("phash", phash).
			Logger(),
	}
}

type Value struct {
	Key   string
	Value interface{}
}

// Session provides logging sessions for drivers
type Session struct {
	Logger zerolog.Logger
}

func (g *Session) AppendLogger(values ...Value) {
	for _, v := range values {
		g.Logger = g.Logger.With().Interface(v.Key, v.Value).Logger()
	}
}

func (g *Session) LogError(e error) {
	g.Logger.Trace().
		Err(e).
		Msg("error")
}

func (g *Session) addValues(values ...Value) zerolog.Logger {
	l := g.Logger
	for _, v := range values {
		l = l.With().Interface(v.Key, v.Value).Logger()
	}
	return l
}
