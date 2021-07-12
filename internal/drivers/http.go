package drivers

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"

	"github.com/antihax/pass/pkg/muxconn"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type httpd struct{}

var server http.Server

func init() {
	h := &httpd{}
	AddDriver([]byte("GET "), h)
	AddDriver([]byte("POST "), h)
	AddDriver([]byte("HEAD "), h)
	AddDriver([]byte("PUT "), h)
	AddDriver([]byte("DELETE "), h)
	AddDriver([]byte("CONNECT "), h)
	AddDriver([]byte("OPTIONS "), h)
	AddDriver([]byte("TRACE "), h)
	AddDriver([]byte("PATCH "), h)

	httpmux := http.NewServeMux()
	httpmux.Handle("/", logger(http.HandlerFunc(h.HandleAll)))
	httpmux.Handle("/loginto.cgi", logger(http.HandlerFunc(h.HandleTrap)))
	httpmux.Handle("/v1.16/version", logger(http.HandlerFunc(h.DockerAPI)))

	server = http.Server{
		ConnContext: SaveMuxInContext,
		Handler:     httpmux,
	}

}

type contextKey struct {
	key string
}

var LoggerContextKey = &contextKey{"logger"}
var ConnContextKey = &contextKey{"conn"}

// Save the logger and tag our driver
func SaveMuxInContext(ctx context.Context, c net.Conn) context.Context {
	if mux, ok := c.(*muxconn.MuxConn); ok {
		ctx = context.WithValue(ctx, LoggerContextKey, mux.GetLogger().With().Str("driver", "http").Logger())
		ctx = context.WithValue(ctx, ConnContextKey, mux)
		return ctx
	}
	return ctx
}

func GetLoggerFromContext(ctx context.Context) zerolog.Logger {
	return ctx.Value(LoggerContextKey).(zerolog.Logger)
}

func GetConnFromContext(ctx context.Context) *muxconn.MuxConn {
	return ctx.Value(ConnContextKey).(*muxconn.MuxConn)
}

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attacklog := GetLoggerFromContext(r.Context())
		conn := GetConnFromContext(r.Context())
		sequence := conn.Sequence()
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			attacklog.Debug().Err(err).Msg("")
		}
		if err = ioutil.WriteFile("./sessions/"+conn.GetUUID()+"-"+strconv.Itoa(sequence), b, 0644); err != nil {
			log.Error().Err(err).Msg("error saving raw data")
		}
		attacklog.Info().Str("url", r.URL.RawPath).Int("sequence", sequence).Msg("URL")

		next.ServeHTTP(w, r)
	})
}

func (s *httpd) ServeTCP(ln net.Listener) error {
	return server.Serve(ln)
}

func (s *httpd) HandleTrap(w http.ResponseWriter, r *http.Request) {
	attacklog := GetLoggerFromContext(r.Context())
	attacklog.Warn().Msg("Trap triggered")
	w.Write(nil)
}

func (s *httpd) HandleAll(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
	<html>
	<body>
	<form action="/loginto.cgi" method="post">
	<input name="user">
	<input name="pass" type="password">
	<button>submit</button>
	</form>
	</body>
	</html>
	`)
}

func (s *httpd) DockerAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"Client":{"Platform":{"Name":"Docker Engine - Community"},"Version":"19.03.8","ApiVersion":"1.40","DefaultAPIVersion":"1.40","GitCommit":"afacb8b","GoVersion":"go1.12.17","Os":"darwin","Arch":"amd64","BuildTime":"Wed Mar 11 01:21:11 2020","Experimental":true},"Server":{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"19.03.8","Details":{"ApiVersion":"1.40","Arch":"amd64","BuildTime":"Wed Mar 11 01:29:16 2020","Experimental":"true","GitCommit":"afacb8b","GoVersion":"go1.12.17","KernelVersion":"4.19.76-linuxkit","MinAPIVersion":"1.12","Os":"linux"}},{"Name":"containerd","Version":"v1.2.13","Details":{"GitCommit":"7ad184331fa3e55e52b890ea95e65ba581ae3429"}},{"Name":"runc","Version":"1.0.0-rc10","Details":{"GitCommit":"dc9208a3303feef5b3839f4323d9beb36df0a9dd"}},{"Name":"docker-init","Version":"0.18.0","Details":{"GitCommit":"fec3683"}}],"Version":"19.03.8","ApiVersion":"1.40","MinAPIVersion":"1.12","GitCommit":"afacb8b","GoVersion":"go1.12.17","Os":"linux","Arch":"amd64","KernelVersion":"4.19.76-linuxkit","Experimental":true,"BuildTime":"2020-03-11T01:29:16.000000000+00:00"}}`)
}
