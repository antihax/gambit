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

var (
	// GlobalContextKey holds globalutils for drivers
	GlobalContextKey = &contextKey{"globalutils"}
)

// GetGlobalFromContext returns store channel from conman context for saving raw packets
func GetGlobalFromContext(ctx context.Context) *GlobalUtils {
	return ctx.Value(GlobalContextKey).(*GlobalUtils)
}
