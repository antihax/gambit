package views

import (
	"net/http"
	"regexp"
	"time"

	"github.com/antihax/gambit/internal/contrive"
	"github.com/gorilla/mux"
)

func init() {
	checkHash := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	contrive.AddRoute("GET", "/hash/{hash}",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			params := mux.Vars(r)

			// sanitize input
			if len(params["hash"]) > 40 || !checkHash.MatchString(params["hash"]) {
				return
			}
			page := newPage(r, "GaMBiT - Hash "+params["hash"])
			page["Hash"] = params["hash"]
			page["Bucket"] = c.Config.BucketURL + "raw/"

			renderTemplate(w,
				"hash.html",
				time.Hour*24*31,
				page)
		})
}
