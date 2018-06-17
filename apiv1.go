package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	yall "yall.in"

	"impractical.co/auth/accounts"
	"impractical.co/auth/grants"
	"impractical.co/auth/scopes"
)

var (
	serverError         = APIError{Error: "server_error", Code: http.StatusInternalServerError}
	invalidGrantError   = APIError{Error: "invalid_grant", Code: http.StatusBadRequest}
	invalidRequestError = APIError{Error: "invalid_request", Code: http.StatusBadRequest}
)

type Service struct {
	GoogleIDVerifier *oidc.IDTokenVerifier
	GoogleClients    []string
	Accounts         accounts.Dependencies
	Scopes           scopes.Dependencies
	Grants           grants.Dependencies
	Log              *yall.Logger
}

type APIError struct {
	Error string `json:"error"`
	Code  int    `json:"-"`
}

func (a APIError) IsZero() bool {
	return a.Error == ""
}

// granter is a generalization of all the ways a user can grant access
// to their account. It needs to be validatable, needs to create a grant,
// can optionally run a function when the grant is used, and must return
// whether it's a redirect flow or not.
type granter interface {

	// if the grant isn't valid, return an error.
	Validate(ctx context.Context) APIError

	// populate a grant with the specified scopes
	Grant(ctx context.Context, scopes []string) grants.Grant

	// optionally perform some action when the grant is used
	Granted(ctx context.Context) error

	// whether the grant type is a redirect flow or should return
	// results as JSON
	Redirects() bool

	// whether the grant type creates and uses a grant immediately
	// within the same request, or if a grant will be passed in
	// as part of the request
	CreatesGrantsInline() bool
}

// populate a url.Values with an APIError, so we can use it
// to generate a query string with the error included.
func errAsQueryParams(apiErr APIError) url.Values {
	return url.Values{
		"error": []string{apiErr.Error},
	}
}

// populate a url.Values with the values from a Token, so we
// can use it to generate a query string with the token included.
func tokenAsQueryParams(token Token) url.Values {
	return url.Values{
		"access_token": []string{token.AccessToken},
		"token_type":   []string{token.TokenType},
		"expires_in":   []string{strconv.Itoa(token.ExpiresIn)},
		"scope":        []string{token.Scope},
	}
}

// merge multiple url.Values into a single url.Values, overwriting
// values from lower-indexed url.Values if multiple url.Values have
// the same key set.
func mergeQueryParams(paramSets ...url.Values) url.Values {
	q := url.Values{}
	for _, params := range paramSets {
		for k, v := range params {
			q[k] = append(q[k], v...)
		}
	}
	return q
}

// return an error, either as JSON output or as a redirect.
func (s Service) returnError(redirect bool, w http.ResponseWriter, r *http.Request, apiErr APIError, redirBase string) {
	if redirect {
		u, err := url.Parse(redirBase)
		if err != nil {
			yall.FromContext(r.Context()).WithError(err).WithField("url", redirBase).Error("Error parsing redirect URL")
			s.returnError(false, w, r, invalidRequestError, redirBase)
			return
		}
		// add our new query params to any the URL may have had
		q := mergeQueryParams(u.Query(), errAsQueryParams(apiErr))
		// build the query back up as part of the URL
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(apiErr.Code)
	enc := json.NewEncoder(w)
	err := enc.Encode(apiErr)
	if err != nil {
		yall.FromContext(r.Context()).WithError(err).Error("Error writing response")
	}
}

// return a token, either as JSON output or as a redirect.
func (s Service) returnToken(redirect bool, w http.ResponseWriter, r *http.Request, token Token, redirBase string) {
	if redirect {
		u, err := url.Parse(redirBase)
		if err != nil {
			yall.FromContext(r.Context()).WithError(err).WithField("url", redirBase).Error("Error parsing redirect URL")
			s.returnError(false, w, r, invalidRequestError, redirBase)
			return
		}
		// add our new query params to any the URL may have had
		q := mergeQueryParams(u.Query(), tokenAsQueryParams(token))
		// build the query back up as part of the URL
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	err := enc.Encode(token)
	if err != nil {
		yall.FromContext(r.Context()).WithError(err).Error("Error writing response")
	}
}

// pull the client credentials out of the request.
func getClientCredentials(r *http.Request) (id, secret, redirect string) {
	id = r.URL.Query().Get("client_id")
	redirect = r.URL.Query().Get("redirect_uri")
	if id != "" {
		return id, secret, redirect
	}
	redirect = ""
	var ok bool
	id, secret, ok = r.BasicAuth()
	if ok {
		return id, secret, redirect
	}
	id = r.PostFormValue("client_id")
	secret = r.PostFormValue("client_secret")
	return id, secret, redirect
}

// check that the client credentials are valid
func (s Service) validateClientCredentials(ctx context.Context, clientID, clientSecret, redirectURI string) APIError {
	if clientID == "" {
		// TODO(paddy): return appropriate error
	}
	if clientSecret != "" && redirectURI != "" {
		// TODO(paddy): return appropriate error
	}
	// TODO(paddy): retrieve client, and validate the credentials
	return APIError{}
}

// find which scopes should be used for a client
// if none are passed in, a default set for the client is used
// if one or more are passed in, scopes the client can't use are stripped
func (s Service) checkScopes(ctx context.Context, clientID string, ids []string) ([]string, APIError) {
	var permittedScopes []scopes.Scope
	var err error
	if len(ids) < 1 {
		permittedScopes, err = s.Scopes.Storer.ListDefault(ctx)
		if err != nil {
			return nil, serverError
		}
	} else {
		resp, err := s.Scopes.Storer.GetMulti(ctx, ids)
		if err != nil {
			return nil, serverError
		}
		for _, v := range resp {
			permittedScopes = append(permittedScopes, v)
		}
	}
	permittedScopes = scopes.FilterByClientID(ctx, permittedScopes, clientID)
	results := make([]string, 0, len(permittedScopes))
	for _, scope := range permittedScopes {
		results = append(results, scope.ID)
	}
	return results, APIError{}
}

// determine what redirect URI to use for the client
func (s Service) getClientRedirectURI(ctx context.Context, clientID, passed string) (string, error) {
	// TODO(paddy): look up client's redirect URIs
	// if client has multiple redirect URIs and passed is empty, return an error
	// if client has one redirect URI and passed is empty, return that URL
	// if client has multiple redirect URIs and passed is a match of one, return that one
	// if client has multiple redirect URIs and passed is not a match for any, return an error
	// if client has no redirect URIs and passed is not empty, return an error
	return "", nil
}

// create a grant in the Storer
func (s Service) createGrant(ctx context.Context, grant grants.Grant) APIError {
	grant, err := grants.FillGrantDefaults(grant)
	if err != nil {
		yall.FromContext(ctx).WithError(err).Error("Error filling grant defaults")
		return serverError
	}
	err = s.Grants.Storer.CreateGrant(ctx, grant)
	if err != nil {
		yall.FromContext(ctx).WithError(err).WithField("grant", grant).Error("Error creating grant")
		return serverError
	}
	return APIError{}
}

// determine which type of grant is being used based on the query params
func (s Service) getGranter(values url.Values, clientID string) granter {
	switch values.Get("grant_type") {
	case "refresh_token":
		return &refreshTokenGranter{
			tokenVal: values.Get("refresh_token"),
			client:   clientID,
		}
	case "google_id":
		return &googleIDGranter{
			tokenVal:     values.Get("id_token"),
			client:       clientID,
			gClients:     s.GoogleClients,
			oidcVerifier: s.GoogleIDVerifier,
			accounts:     s.Accounts.Storer,
		}
	}
	return nil
}

// handle the access token request endpoint
// this endpoint is used when the user is ready to trade an existing grant for an
// access token.
func (s Service) handleAccessTokenRequest(w http.ResponseWriter, r *http.Request) {
	// explicitly parse the form, so we can handle the error
	err := r.ParseForm()
	if err != nil {
		yall.FromContext(r.Context()).WithError(err).Error("Error parsing form")
		s.returnError(false, w, r, invalidRequestError, "")
		return
	}

	// figure out which client we're dealing with
	clientID, clientSecret, redirectURI := getClientCredentials(r)

	// make sure the client is who they say they are
	clientErr := s.validateClientCredentials(r.Context(), clientID, clientSecret, redirectURI)
	if !clientErr.IsZero() {
		yall.FromContext(r.Context()).WithField("api_error", clientErr).Debug("Error validating client")
		s.returnError(false, w, r, invalidRequestError, "")
		return
	}

	// figure out what type of grant we're dealing with
	g := s.getGranter(r.PostForm, clientID)
	if g == nil {
		// if g is nil, that means it's not a match for our supported types
		yall.FromContext(r.Context()).WithField("grant_type", r.PostForm.Get("grant_type")).Debug("Unsupported grant type")
		s.returnError(false, w, r, APIError{
			Error: "unsupported_response_type",
			Code:  http.StatusBadRequest,
		}, "")
		return
	}

	// figure out which redirect URI to use for our client
	redirectURI, err = s.getClientRedirectURI(r.Context(), clientID, redirectURI)
	if err != nil {
		yall.FromContext(r.Context()).WithField("client_id", clientID).WithField("redirect_url", redirectURI).
			WithError(err).Error("Error determining redirect URI.")
		s.returnError(false, w, r, serverError, "")
		return
	}

	// validate the grant
	apiErr := g.Validate(r.Context())
	if !apiErr.IsZero() {
		yall.FromContext(r.Context()).WithField("error", apiErr).Debug("Error validating grant")
		s.returnError(g.Redirects(), w, r, apiErr, redirectURI)
		return
	}

	// figure out what scopes we should be using
	scopes := strings.Split(r.FormValue("scope"), " ")
	scopes, apiErr = s.checkScopes(r.Context(), clientID, scopes)
	if !apiErr.IsZero() {
		yall.FromContext(r.Context()).WithField("error", apiErr).Debug("Error checking scopes")
		s.returnError(g.Redirects(), w, r, apiErr, redirectURI)
		return
	}

	// retrieve or fill out our grant fields
	grant := g.Grant(r.Context(), scopes)

	// create and store our grant for granters
	// that don't create their own
	if g.CreatesGrantsInline() {
		// build our grant
		grant.CreateIP = grant.UseIP

		// store the grant
		apiErr = s.createGrant(r.Context(), grant)
		if !apiErr.IsZero() {
			yall.FromContext(r.Context()).WithField("error", apiErr).Debug("Error creating grant")
			s.returnError(g.Redirects(), w, r, apiErr, redirectURI)
			return
		}
	}

	grant, err = s.Grants.Storer.ExchangeGrant(r.Context(), grants.GrantUse{
		Grant: grant.ID,
		IP:    getIP(r),
		Time:  time.Now(),
	})

	if err == grants.ErrGrantAlreadyUsed {
		// TODO(paddy): return an appropriate error
		return
	} else if err == grants.ErrGrantNotFound {
		// TODO(paddy): return an appropriate error
		return
	} else if err != nil {
		yall.FromContext(r.Context()).WithError(err).Error("error exchanging grant")
		s.returnError(g.Redirects(), w, r, serverError, redirectURI)
		return
	}

	// issue tokens using the grant
	token, apiErr := s.issueTokens(r.Context(), grant)
	if !apiErr.IsZero() {
		yall.FromContext(r.Context()).WithField("error", apiErr).Debug("Error issuing tokens")
		s.returnError(g.Redirects(), w, r, apiErr, redirectURI)
		return
	}

	// call any functionality that we need to to mark the grant as used
	err = g.Granted(r.Context())
	if err != nil {
		yall.FromContext(r.Context()).WithField("grant", g).WithError(err).Error("Error marking grant as used")
	}

	// return our tokens
	s.returnToken(g.Redirects(), w, r, token, redirectURI)
}
