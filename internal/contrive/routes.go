package contrive

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
)

// Structure for handling routes
type route struct {
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type contextKey struct {
	key string
}

var GlobalsKey = &contextKey{"GlobalKey"}

// Globals for routes so we can add them in `func init()`
var routes []route

// AddRoute adds a non-authenticated web handler to the route list
// this should be called by func init() within the views package
func AddRoute(method string, pattern string, handlerFunc http.HandlerFunc) {
	routes = append(routes, route{method, pattern, handlerFunc})
}

// Middleware to add global AppContext to a request.Context
func contextWithGlobals(ctx context.Context, a *Contrive) context.Context {
	return context.WithValue(ctx, GlobalsKey, a)
}

// GlobalsFromContext returns attached AppContext from a request.Context
func GlobalsFromContext(ctx context.Context) *Contrive {
	return ctx.Value(GlobalsKey).(*Contrive)
}

// addGlobals to the view
func (c *Contrive) addGlobals(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := contextWithGlobals(req.Context(), c)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// NewRouter sets up the routes that were added.
func (c *Contrive) NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(false)
	// Add public routes
	for _, route := range routes {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Handler(c.addGlobals(route.HandlerFunc))
	}

	router.PathPrefix("/s/").Handler(http.StripPrefix("/s/",
		http.FileServer(http.Dir("static"))))

	return router
}
