package gctx

import (
	"context"

	"github.com/antihax/gambit/internal/muxconn"
	"github.com/antihax/gambit/internal/store"
	"github.com/rs/zerolog"
)

var (
	IPAddress string
)

type contextKey struct {
	key string
}

var LoggerContextKey = &contextKey{"logger"}
var HashContextKey = &contextKey{"hash"}
var ConnContextKey = &contextKey{"conn"}
var StoreContextKey = &contextKey{"store"}

func GetStoreFromContext(ctx context.Context) chan store.File {
	return ctx.Value(StoreContextKey).(chan store.File)
}

func GetHashFromContext(ctx context.Context) string {
	return ctx.Value(HashContextKey).(string)
}

func GetLoggerFromContext(ctx context.Context) zerolog.Logger {
	return ctx.Value(LoggerContextKey).(zerolog.Logger)
}

func GetConnFromContext(ctx context.Context) *muxconn.MuxConn {
	return ctx.Value(ConnContextKey).(*muxconn.MuxConn)
}
