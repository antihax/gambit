// Package gctx provides glue for contexts used by conman
package gctx

import (
	"context"

	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/rs/zerolog"
)

var (
	// IPAddress holds the bind address from the configuration to be shared with drivers
	IPAddress string
)

// contextKey for conman contexts
type contextKey struct {
	key string
}

var (
	// LoggerContextKey holds the base zerolog passed to drivers
	LoggerContextKey = &contextKey{"logger"}

	// HashContextKey provides the base hash from the inital packet sniff
	HashContextKey = &contextKey{"hash"}

	// ConnContextKey contains the muxconn to aid in further sniffing
	ConnContextKey = &contextKey{"conn"}

	// StoreContextKey allows drivers to access the store channel for saving raw packet contents
	StoreContextKey = &contextKey{"store"}
)

// GetStoreFromContext returns store channel from conman context for saving raw packets
func GetStoreFromContext(ctx context.Context) chan store.File {
	return ctx.Value(StoreContextKey).(chan store.File)
}

// GetHashFromContext returns the base hash from the initial sniff
func GetHashFromContext(ctx context.Context) string {
	return ctx.Value(HashContextKey).(string)
}

// GetLoggerFromContext returns the zero log from the conman context
func GetLoggerFromContext(ctx context.Context) zerolog.Logger {
	return ctx.Value(LoggerContextKey).(zerolog.Logger)
}

// GetConnFromContext returns the muxconn for further sniffing
func GetConnFromContext(ctx context.Context) *muxconn.MuxConn {
	return ctx.Value(ConnContextKey).(*muxconn.MuxConn)
}
