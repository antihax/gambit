package drivers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/antihax/gambit/internal/conman/gctx"
	"github.com/antihax/gambit/pkg/muxconn"
)

var server http.Server

type httpd struct{}

// contextKey for conman contexts
type contextKey struct {
	key string
}

var (
	sessionContextKey = &contextKey{"sessionlogger"}
)

func (s *httpd) ServeTCP(ln net.Listener) {
	server.Serve(ln)
}
func (s *httpd) Patterns() [][]byte {
	return [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("HEAD "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("CONNECT "),
		[]byte("OPTIONS "),
		[]byte("TRACE "),
		[]byte("PATCH "),
	}
}

func init() {
	h := &httpd{}
	AddDriver(h)
	httpmux := http.NewServeMux()

	// Catch all
	httpmux.Handle("/", h.logger(http.HandlerFunc(h.handleAll)))
	httpmux.Handle("/loginto.cgi", h.logger(http.HandlerFunc(h.handleTrap)))

	// Docker
	httpmux.Handle("/v1.16/version", h.logger(http.HandlerFunc(h.dockerVersion)))
	httpmux.Handle("/_ping", h.logger(http.HandlerFunc(h.dockerPing)))
	httpmux.Handle("/v1.24/containers/create", h.logger(http.HandlerFunc(h.dockerContainerCreated)))
	httpmux.Handle("/v1.24/containers/e90e34656806/attach", h.logger(http.HandlerFunc(h.dockere90e34656806attach)))

	// PHPUnit
	httpmux.Handle("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", h.logger(http.HandlerFunc(h.phpunit)))

	server = http.Server{
		ConnContext: h.SaveMuxInContext,
		Handler:     httpmux,
	}
}

// copy context values to the http context
func (s *httpd) SaveMuxInContext(ctx context.Context, c net.Conn) context.Context {
	if mux, ok := c.(*muxconn.MuxConn); ok {
		return context.WithValue(ctx, gctx.GlobalContextKey, gctx.GetGlobalFromContext(mux.Context, ""))
	}
	return ctx
}

func newContextWithLogger(ctx context.Context, req *http.Request, logger *gctx.Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, logger)
}

func loggerFromContext(ctx context.Context) *gctx.Session {
	return ctx.Value(sessionContextKey).(*gctx.Session)
}

func (s *httpd) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		glob := gctx.GetGlobalFromContext(r.Context(), "http")
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			glob.LogError(err)
		}

		l := glob.NewSession(glob.MuxConn.Sequence(), StoreHash(b, glob.Store))
		l.AppendLogger(gctx.Value{Key: "url", Value: r.URL.Path})
		l.Logger.Info().Msg("url")
		r = r.WithContext(newContextWithLogger(r.Context(), r, l))

		next.ServeHTTP(w, r)
	})
}

func (s *httpd) handleAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
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

func (s *httpd) handleTrap(w http.ResponseWriter, r *http.Request) {
	loggerFromContext(r.Context()).
		ATTACKEntPasswordGuessing(
			gctx.Value{Key: "user", Value: r.Form.Get("user")},
			gctx.Value{Key: "pass", Value: r.Form.Get("pass")},
		)

	w.Header().Set("Content-Type", "text/html")
	w.Write(nil)
}

// ######### Docker Handlers
func (s *httpd) dockerVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"Client":{"Platform":{"Name":"Docker Engine - Community"},"Version":"19.03.8","ApiVersion":"1.40","DefaultAPIVersion":"1.40","GitCommit":"afacb8b","GoVersion":"go1.12.17","Os":"darwin","Arch":"amd64","BuildTime":"Wed Mar 11 01:21:11 2020","Experimental":true},"Server":{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"19.03.8","Details":{"ApiVersion":"1.40","Arch":"amd64","BuildTime":"Wed Mar 11 01:29:16 2020","Experimental":"true","GitCommit":"afacb8b","GoVersion":"go1.12.17","KernelVersion":"4.19.76-linuxkit","MinAPIVersion":"1.12","Os":"linux"}},{"Name":"containerd","Version":"v1.2.13","Details":{"GitCommit":"7ad184331fa3e55e52b890ea95e65ba581ae3429"}},{"Name":"runc","Version":"1.0.0-rc10","Details":{"GitCommit":"dc9208a3303feef5b3839f4323d9beb36df0a9dd"}},{"Name":"docker-init","Version":"0.18.0","Details":{"GitCommit":"fec3683"}}],"Version":"19.03.8","ApiVersion":"1.40","MinAPIVersion":"1.12","GitCommit":"afacb8b","GoVersion":"go1.12.17","Os":"linux","Arch":"amd64","KernelVersion":"4.19.76-linuxkit","Experimental":true,"BuildTime":"2020-03-11T01:29:16.000000000+00:00"}}`)
}

func (s *httpd) dockerPing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `OK`)
}

func (s *httpd) dockerContainerCreated(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"Id":"e90e34656806","Warnings":[]}`)
	glob := loggerFromContext(r.Context())
	glob.ATTACKEntDeployContainer(gctx.Value{Key: "system", Value: "docker"})
}

// [TODO] build framework for reading and writing these streams
func (s *httpd) dockere90e34656806attach(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusSwitchingProtocols)
	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "tcp")
	glob := loggerFromContext(r.Context())
	glob.ATTACKEntContainerAdministrationCommand(gctx.Value{Key: "system", Value: "docker"})
	fmt.Fprintf(w, ``)
}

// ######### Wordpress Handlers

// phpunit\
func (s *httpd) phpunit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `85af727fd022d3a13e7972fd6a418582`)
	glob := loggerFromContext(r.Context())
	glob.ATTACKEntExploitPublicFacingApplication(
		gctx.Value{Key: "system", Value: "wordpress"},
		gctx.Value{Key: "cve", Value: "CVE-2017-9841"},
	)
}
