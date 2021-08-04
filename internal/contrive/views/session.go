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
	contrive.AddRoute("GET", "/session/{session}",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			params := mux.Vars(r)

			// sanitize input
			if len(params["session"]) > 40 || !checkHash.MatchString(params["session"]) {
				return
			}
			page := newPage(r, "GaMBiT - Session "+params["session"])
			page["Session"] = params["session"]
			page["Bucket"] = c.Config.BucketURL + "sessions/"

			renderTemplate(w,
				"session.html",
				time.Hour*24*31,
				page)
		})
}
