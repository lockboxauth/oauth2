package oauth2

import (
	"net/http"
	"strings"

	"darlinggo.co/trout/v2"
	yall "yall.in"
)

func logEndpoint(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := yall.FromContext(r.Context()).
			WithField("endpoint", r.Header.Get("Trout-Pattern")).
			WithField("method", r.Method)
		for k, v := range trout.RequestVars(r) {
			log = log.WithField("url."+strings.ToLower(k), v)
		}
		r = r.WithContext(yall.InContext(r.Context(), log))
		log.Debug("serving request")
		h.ServeHTTP(w, r)
		log.Debug("served request")
	})
}

// Server returns an `http.Handler` that will serve two OAuth2-esque endpoints,
// /token and /authorize. If this `http.Handler` will be served as a path from
// a ServeMux, like "/auth/", `prefix` should be set to that path to allow the
// `http.Handler`'s router to accurately route to the endpoints.
func (s Service) Server(prefix string) http.Handler {
	var router trout.Router
	router.SetPrefix(prefix)

	router.Endpoint("/token").Methods("POST").
		Handler(logEndpoint(http.HandlerFunc(
			s.handleAccessTokenRequest)))
	router.Endpoint("/authorize").Methods("POST").
		Handler(logEndpoint(http.HandlerFunc(
			s.handleGrantRequest)))

	return router
}
