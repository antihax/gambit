package views

import (
	"net/http"
	"time"

	"github.com/antihax/gambit/internal/contrive"
)

func init() {

	contrive.AddRoute("GET", "/recentPasswords",
		func(w http.ResponseWriter, r *http.Request) {
			//c := contrive.GlobalsFromContext(r.Context())
			page := newPage(r, "GaMBiT - Recent Passwords")

			renderTemplate(w,
				"recentPasswords.html",
				time.Hour*24*31,
				page)
		})
}
