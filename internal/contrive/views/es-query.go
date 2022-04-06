package views

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/antihax/gambit/internal/contrive"
	"github.com/gorilla/mux"
)

func init() {
	checkHash := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	contrive.AddRoute("GET", "/api/recent-sse",
		func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
				return
			}
			c := contrive.GlobalsFromContext(r.Context())
			ch := c.NewRecentClient()
			defer close(ch)

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")

			for {
				select {
				case msg := <-ch:
					fmt.Fprintf(w, "data: %s\n\n", msg)
					flusher.Flush()
				case <-r.Context().Done():
					flusher.Flush()
					return
				}
			}
		})

	contrive.AddRoute("GET", "/api/unknowns",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			data, err := c.ESQ.Unknowns()
			if err != nil {
				log.Println(err)
				return
			}
			renderJSON(w, data.User.Buckets, time.Hour)
		})

	contrive.AddRoute("GET", "/api/recentPasswords",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			data, err := c.ESQ.RecentPasswords()
			if err != nil {
				log.Println(err)
				return
			}
			renderJSON(w, data, time.Hour)
		})

	contrive.AddRoute("GET", "/api/passwordList",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			data, err := c.ESQ.PasswordList()
			if err != nil {
				log.Println(err)
				return
			}
			renderJSON(w, data, time.Hour*24)
		})

	contrive.AddRoute("GET", "/api/recent",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			data, err := c.ESQ.Recent()
			if err != nil {
				log.Println(err)
				return
			}
			renderJSON(w, data, time.Second*30)
		})

	contrive.AddRoute("GET", "/api/sessionsForHash/{hash}",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())

			params := mux.Vars(r)

			// sanitize input
			if len(params["hash"]) > 40 || !checkHash.MatchString(params["hash"]) {
				return
			}

			data, err := c.ESQ.SessionsForHash(params["hash"])
			if err != nil {
				log.Println(err)
				return
			}
			renderJSON(w, data, time.Minute*5)
		})
}
