package oauth2

import (
	"net/http"

	"darlinggo.co/trout"
	yall "yall.in"
)

func (s Service) contextLogger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := s.Log.WithRequest(r).WithField("endpoint", r.Header.Get("Trout-Pattern"))
		r = r.WithContext(yall.InContext(r.Context(), log))
		log.Debug("serving request")
		h.ServeHTTP(w, r)
	})
}

func (s Service) Server(prefix string) http.Handler {
	var router trout.Router
	router.SetPrefix(prefix)

	router.Endpoint("/token").Methods("POST").Handler(s.contextLogger(http.HandlerFunc(s.handleAccessTokenRequest)))

	return router
}
