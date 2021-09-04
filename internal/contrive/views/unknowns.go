package views

import (
	"net/http"
	"time"

	"github.com/antihax/gambit/internal/contrive"
)

func init() {
	contrive.AddRoute("GET", "/unknowns",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			page := newPage(r, "GaMBiT - Unknown Packets")
			page["Bucket"] = c.Config.BucketURL + "raw/"

			renderTemplate(w,
				"unknowns.html",
				time.Hour*24*31,
				page)
		})
}
