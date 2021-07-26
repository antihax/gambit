package views

import (
	"net/http"
	"time"

	"github.com/antihax/gambit/internal/contrive"
)

func init() {
	contrive.AddRoute("GET", "/",
		func(w http.ResponseWriter, r *http.Request) {
			renderTemplate(w,
				"index.html",
				time.Hour*24*31,
				newPage(r, "GaMBiT"))
		})
}
