// Package gctx provides glue for contexts used by conman
package gctx

import (
	"context"

	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/rs/zerolog"
)

var ()

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

func GlobalUtilsContext(ctx context.Context, globals *GlobalUtils) context.Context {
	return context.WithValue(ctx, GlobalContextKey, globals)
}

// GlobalUtils provides utils for drivers
type GlobalUtils struct {
	MuxConn  *muxconn.MuxConn
	Logger   zerolog.Logger
	BaseHash string
	Store    chan store.File
}

// GetGlobalFromContext returns store channel from conman context for saving raw packets
func GetGlobalFromContext(ctx context.Context, driver string) *GlobalUtils {
	c := ctx.Value(GlobalContextKey).(*GlobalUtils)
	if driver != "" {
		c.Logger = c.Logger.With().Str("driver", driver).Logger()
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

func (g *GlobalUtils) NewSession(sessionID int, phash string) *Session {
	return &Session{
		Logger: g.Logger.With().
			Int("session", sessionID).
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

// MITRE ATT&CK outputs
// TriedPassword logs a password attempt

func (g *Session) TriedPassword(user, pass string, values ...Value) {
	l := g.addValues(values...)
	l.Warn().
		Str("technique", "T1110").
		Str("user", user).
		Str("pass", pass).
		Msg("tried password")
}

// TriedKey logs a public key attempt
func (g *Session) TriedKey(user, key, keytype string, values ...Value) {
	l := g.addValues(values...)
	l.Warn().
		Str("technique", "T1110").
		Str("user", user).
		Str("pubkey", key).
		Str("pubkeytype", key).
		Msg("tried public key")
}

func (g *Session) TriedICSPointAndTag(command string, values ...Value) {
	l := g.addValues(values...)
	l.Warn().
		Str("technique", "T0861").
		Str("opCode", command).
		Msg("tried point or tag")
}

func (g *Session) TriedDeployContainer(values ...Value) {
	l := g.addValues(values...)
	l.Warn().
		Str("technique", "T1610").
		Msg("deployed container")
}

func (g *Session) TriedExecContainer(values ...Value) {
	l := g.addValues(values...)
	l.Warn().
		Str("technique", "T1609").
		Msg("exec on container")
}

func (g *Session) TriedExploitingPublicApplication(values ...Value) {
	l := g.addValues(values...)
	l.Warn().
		Str("technique", "T1190").
		Msg("exploit public application")
}

func (g *Session) TriedActiveProbe(values ...Value) {
	l := g.addValues(values...)
	l.Warn().
		Str("technique", "T1595").
		Msg("probing service")
}
