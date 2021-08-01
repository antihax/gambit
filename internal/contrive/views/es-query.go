package views

import (
	"context"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/antihax/gambit/internal/contrive"
	"github.com/gorilla/mux"
	"nhooyr.io/websocket"
)

func init() {
	checkHash := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	contrive.AddRoute("GET", "/api/recent-ws",
		func(w http.ResponseWriter, r *http.Request) {
			c := contrive.GlobalsFromContext(r.Context())
			ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				log.Println(err)
				return
			}
			defer ws.Close(websocket.StatusNormalClosure, "")
			ch := c.NewRecentClient()
			defer close(ch)
			ctx, cancel := context.WithTimeout(r.Context(), time.Minute*10)
			defer cancel()

			// ignore anything from the client
			ctx = ws.CloseRead(ctx)

			for {
				select {
				case <-ctx.Done():
					ws.Close(websocket.StatusNormalClosure, "")
					return
				case st := <-ch:
					err = ws.Write(ctx, websocket.MessageText, st)
					if err != nil {
						log.Println(err)
						return
					}
				}
			}
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
