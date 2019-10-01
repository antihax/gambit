package drivers

import (
	"fmt"
	"net"
	"net/http"
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
	fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}
