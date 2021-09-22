package conman

import (
	"net/http"
	_ "net/http/pprof"
)

func runPProf() {
	http.ListenAndServe("localhost:9900", nil)
}
