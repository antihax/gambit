package drivers

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
)

func init() {
	h := &httpd{}
	AddDriver([]byte("GET "), h)
	AddDriver([]byte("POST "), h)
	AddDriver([]byte("HEAD "), h)
	AddDriver([]byte("PUT "), h)
	AddDriver([]byte("DELETE "), h)

	http.HandleFunc("/", h.HelloServer)
}

type httpd struct{}

func (s *httpd) ServeTCP(ln net.Listener) error {
	return http.Serve(ln, nil)
}

func (s *httpd) HelloServer(w http.ResponseWriter, r *http.Request) {

	b, _ := httputil.DumpRequest(r, true)
	fmt.Printf("%s\n", b)
	fmt.Fprintf(w, `
	<html>
	<body>
	<form action="/login.cgi" method="post">
	<input name="user">
	<input name="pass" type="password">
	<button>submit</button>
	</form>
	</body>
	</html>
	`)
}
