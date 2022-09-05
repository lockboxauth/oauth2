package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	yall "yall.in"

	"lockbox.dev/accounts"
	"lockbox.dev/clients"
	"lockbox.dev/grants"
	"lockbox.dev/scopes"
	"lockbox.dev/sessions"
	"lockbox.dev/tokens"
)

type responseMethod int

const (
	rmRedirect responseMethod = iota
	rmOOB
)

var (
	serverError         = APIError{Error: "server_error", Code: http.StatusInternalServerError}
	invalidGrantError   = APIError{Error: "invalid_grant", Code: http.StatusBadRequest}
	invalidRequestError = APIError{Error: "invalid_request", Code: http.StatusBadRequest}
	errInvalidClientURI = errors.New("invalid URI")
)

// Service contains all the dependencies needed to complete the authentication
// and authorization flow.
type Service struct {
	GoogleIDVerifier *oidc.IDTokenVerifier
	GoogleClients    []string
	TokenExpiresIn   int
	Accounts         accounts.Dependencies
	Clients          clients.Storer
	Grants           grants.Dependencies
	Refresh          tokens.Dependencies
	Scopes           scopes.Dependencies
	Sessions         sessions.Dependencies
	Log              *yall.Logger
	Emailer          emailer
}

// APIError is an error response that should be returned to the end user. It
// generally isn't meant for programmatic inspection.
type APIError struct {
	Error string `json:"error"`
	Code  int    `json:"-"`
}

// IsZero returns true if the APIError should be considered empty or the zero
// value.
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

	// return the ID of the profile the Grant is for.
	ProfileID(ctx context.Context) string

	// return the ID of the account the Grant is for.
	AccountID(ctx context.Context) string

	// populate a grant with the specified scopes
	Grant(ctx context.Context, requestedScopes []string) grants.Grant

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

type grantCreator interface {
	GetAccount(ctx context.Context) (accounts.Account, APIError)
	FillGrant(ctx context.Context, account accounts.Account, requestedScopes []string) (grants.Grant, APIError)
	ResponseMethod() responseMethod
	HandleOOBGrant(ctx context.Context, grant grants.Grant) error
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

// populate a url.Values with the values from a Grant, so we
// can use it to generate a query string with the grant included.
func grantAsQueryParams(grant grants.Grant) url.Values {
	return url.Values{
		"code":      []string{grant.SourceID},
		"code_type": []string{grant.SourceType},
	}
}

// merge multiple url.Values into a single url.Values, overwriting
// values from lower-indexed url.Values if multiple url.Values have
// the same key set.
func mergeQueryParams(paramSets ...url.Values) url.Values {
	query := url.Values{}
	for _, params := range paramSets {
		for k, v := range params {
			query[k] = append(query[k], v...)
		}
	}
	return query
}

// check that we're using a supported content type
func isContentType(ctx context.Context, r *http.Request, contentTypes ...string) bool {
	contentTypeHeader := r.Header.Get("Content-type")
	if contentTypeHeader == "" {
		contentTypeHeader = "application/octet-stream"
		yall.FromContext(ctx).Debug("no content-type header set, assuming application/octet-stream")
	}

	for _, v := range strings.Split(contentTypeHeader, ",") {
		contentType, _, err := mime.ParseMediaType(v)
		if err != nil {
			yall.FromContext(ctx).WithError(err).WithField("content_type", v).WithField("content_type_header", contentTypeHeader).Debug("error parsing media type")
			break
		}
		for _, candidate := range contentTypes {
			if contentType == candidate {
				yall.FromContext(ctx).WithField("content_type", candidate).Debug("suitable content-type header found")
				return true
			}
		}
	}
	return false
}

// nolint: contextcheck // this is a false positive, we're actually chaining contexts correctly
func (s Service) redirectError(w http.ResponseWriter, r *http.Request, apiErr APIError, redirBase string) {
	if redirBase == "" {
		yall.FromContext(r.Context()).Error("redirecting but no redirectURL set")
		s.renderError(w, r, apiErr)
		return
	}
	redirectURL, err := url.Parse(redirBase)
	if err != nil {
		yall.FromContext(r.Context()).WithError(err).WithField("url", redirBase).Error("Error parsing redirect URL")
		s.renderError(w, r, apiErr)
		return
	}
	// add our new query params to any the URL may have had
	q := mergeQueryParams(redirectURL.Query(), errAsQueryParams(apiErr))
	// build the query back up as part of the URL
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// nolint: contextcheck // this is a false positive, we're actually chaining contexts correctly
func (Service) renderError(w http.ResponseWriter, r *http.Request, apiErr APIError) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(apiErr.Code)
	enc := json.NewEncoder(w)
	if err := enc.Encode(apiErr); err != nil {
		yall.FromContext(r.Context()).WithError(err).Error("Error writing response")
	}
}

func (s Service) redirectToken(w http.ResponseWriter, r *http.Request, token Token, redirBase string) {
	redirectURL, err := url.Parse(redirBase)
	if err != nil {
		yall.FromContext(r.Context()).WithError(err).WithField("url", redirBase).Error("Error parsing redirect URL")
		s.renderError(w, r, invalidRequestError)
		return
	}
	// add our new query params to any the URL may have had
	q := mergeQueryParams(redirectURL.Query(), tokenAsQueryParams(token))
	// build the query back up as part of the URL
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (Service) renderToken(w http.ResponseWriter, r *http.Request, token Token) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	if err := enc.Encode(token); err != nil {
		yall.FromContext(r.Context()).WithError(err).Error("Error writing response")
	}
}

func (s Service) redirectGrant(w http.ResponseWriter, r *http.Request, grant grants.Grant, redirBase string) {
	redirectURL, err := url.Parse(redirBase)
	if err != nil {
		yall.FromContext(r.Context()).WithError(err).WithField("url", redirBase).Error("Error parsing redirect URL")
		s.renderError(w, r, invalidRequestError)
		return
	}
	// add our new query params to any the URL may have had
	q := mergeQueryParams(redirectURL.Query(), grantAsQueryParams(grant))
	// build the query back up as part of the URL
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (Service) returnGrantOOB(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
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
	log := yall.FromContext(ctx)
	if clientID == "" {
		log.Debug("no client ID specified")
		return APIError{Code: http.StatusUnauthorized, Error: "invalid_client"}
	}
	if clientSecret != "" && redirectURI != "" {
		log.Debug("client secret and redirect URI both set")
		return APIError{Code: http.StatusUnauthorized, Error: "invalid_client"}
	}
	client, err := s.Clients.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, clients.ErrClientNotFound) {
			log.Debug("client not found")
			return APIError{Code: http.StatusUnauthorized, Error: "invalid_client"}
		}
		log.WithError(err).Error("error retrieving client")
		return serverError
	}
	err = client.CheckSecret(clientSecret)
	if err != nil {
		if errors.Is(err, clients.ErrIncorrectSecret) {
			log.Debug("incorrect client secret")
			return APIError{Code: http.StatusUnauthorized, Error: "invalid_client"}
		}
		log.WithError(err).Error("error checking client secret")
		return serverError
	}
	return APIError{}
}

// find which scopes should be used for a client
// if none are passed in, a default set for the client is used
// if one or more are passed in, scopes the client and account can't use are stripped
func (s Service) checkScopes(ctx context.Context, clientID, profileID, accountID string, ids []string) ([]string, APIError) { //nolint:revive // this needs refactored, I know
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
		if len(resp) != len(ids) {
			yall.FromContext(ctx).WithField("scope_ids", ids).WithField("scope_results", resp).
				Warn("fewer scopes than requested returned, one likely doesn't exist")
		}
		for _, v := range resp {
			permittedScopes = append(permittedScopes, v)
		}
	}
	permittedScopes = scopes.FilterByClientID(ctx, permittedScopes, clientID)
	permittedScopes = scopes.FilterByUserID(ctx, permittedScopes, accountID)
	// TODO: filter scopes by profile ID
	_ = profileID // gets rid of the revive error for not using the argument
	results := make([]string, 0, len(permittedScopes))
	for _, scope := range permittedScopes {
		results = append(results, scope.ID)
	}
	return results, APIError{}
}

// determine what redirect URI to use for the client
func (s Service) getClientRedirectURI(ctx context.Context, clientID, passed string) (string, error) {
	uris, err := s.Clients.ListRedirectURIs(ctx, clientID)
	if err != nil {
		return "", err
	}
	if passed == "" {
		switch {
		case len(uris) < 1:
			return "", nil
		case len(uris) > 1:
			return "", fmt.Errorf("%w: client has multiple redirect URIs, none passed", errInvalidClientURI)
		case len(uris) == 1:
			return uris[0].URI, nil
		}
	}
	switch {
	case len(uris) >= 1:
		for _, uri := range uris {
			if passed == uri.URI {
				return uri.URI, nil
			}
		}
		return "", fmt.Errorf("%w: passed URI not a client URI", errInvalidClientURI)
	case len(uris) < 1:
		return "", fmt.Errorf("%w: client has no URIs, but one was passed", errInvalidClientURI)
	}
	return "", fmt.Errorf("%w: impossible error", errInvalidClientURI)
}

// create a grant in the Storer
func (s Service) createGrant(ctx context.Context, grant grants.Grant) (grants.Grant, APIError) {
	grant, err := grants.FillGrantDefaults(grant)
	if err != nil {
		yall.FromContext(ctx).WithError(err).Error("Error filling grant defaults")
		return grant, serverError
	}
	err = s.Grants.Storer.CreateGrant(ctx, grant)
	if err != nil {
		if errors.Is(err, grants.ErrGrantSourceAlreadyUsed) {
			yall.FromContext(ctx).Debug("grant source already used")
			return grant, invalidGrantError
		}
		yall.FromContext(ctx).WithError(err).WithField("grant", grant).Error("Error creating grant")
		return grant, serverError
	}
	return grant, APIError{}
}

// determine which type of grant is being used based on the query params
func (s Service) getGranter(values url.Values, clientID string) granter { //nolint:ireturn // the point of the method is to pick an interface implementation
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
	case "email":
		return &emailGranter{
			code:     values.Get("code"),
			clientID: clientID,
			grants:   s.Grants.Storer,
		}
	}
	return nil
}

func (s Service) getGrantCreator(values url.Values, clientID string) grantCreator { //nolint:ireturn // the point of the method is to pick an interface implementation
	if values.Get("response_type") == "email" {
		return &emailGrantCreator{
			email:    values.Get("email"),
			client:   clientID,
			accounts: s.Accounts.Storer,
			emailer:  s.Emailer,
		}
	}
	return nil
}

// handle the access token request endpoint
// this endpoint is used when the user is ready to trade an existing grant for an
// access token.
func (s Service) handleAccessTokenRequest(w http.ResponseWriter, r *http.Request) {
	log := yall.FromContext(r.Context())

	// check our content-type. r.ParseForm() only works if the header is
	// set to application/x-www-form-urlencoded
	if !isContentType(r.Context(), r, "application/x-www-form-urlencoded") {
		log.WithField("content_type", r.Header.Get("Content-Type")).Debug("invalid content type")
		s.renderError(w, r, APIError{
			Error: "unsupported_content_type",
			Code:  http.StatusUnsupportedMediaType,
		})
		return
	}

	// explicitly parse the form, so we can handle the error
	err := r.ParseForm()
	if err != nil {
		log.WithError(err).Error("Error parsing form")
		s.renderError(w, r, invalidRequestError)
		return
	}

	// figure out which client we're dealing with
	clientID, clientSecret, redirectURI := getClientCredentials(r)
	log = log.WithField("oauth2_client_id", clientID).WithField("redirect_uri_given", redirectURI)

	// make sure the client is who they say they are
	clientErr := s.validateClientCredentials(yall.InContext(r.Context(), log), clientID, clientSecret, redirectURI)
	if !clientErr.IsZero() {
		log.WithField("api_error", clientErr).Debug("Error validating client")
		s.renderError(w, r, clientErr)
		return
	}

	log.WithField("grant_type", r.PostForm.Get("grant_type"))

	// figure out what type of grant we're dealing with
	granter := s.getGranter(r.PostForm, clientID)
	if granter == nil {
		// if g is nil, that means it's not a match for our supported types
		log.Debug("Unsupported grant type")
		s.renderError(w, r, APIError{
			Error: "unsupported_response_type",
			Code:  http.StatusBadRequest,
		})
		return
	}

	// figure out which redirect URI to use for our client
	redirectURI, err = s.getClientRedirectURI(yall.InContext(r.Context(), log), clientID, redirectURI)
	if err != nil {
		log.WithError(err).Error("Error determining redirect URI.")
		s.renderError(w, r, serverError)
		return
	}
	log = log.WithField("redirect_uri", redirectURI)

	// validate the grant
	apiErr := granter.Validate(yall.InContext(r.Context(), log))
	if !apiErr.IsZero() {
		log.WithField("error_code", apiErr.Code).WithField("error_type", apiErr.Error).Debug("Error validating grant")
		if granter.Redirects() {
			s.redirectError(w, r, apiErr, redirectURI)
			return
		}
		s.renderError(w, r, apiErr)
		return
	}

	// figure out what scopes we should be using
	requestedScopes := strings.Split(r.FormValue("scope"), " ")
	log = log.WithField("scopes_requested", requestedScopes)
	logCtx := yall.InContext(r.Context(), log)
	checkedScopes, apiErr := s.checkScopes(logCtx, clientID, granter.ProfileID(logCtx), granter.AccountID(logCtx), requestedScopes)
	if !apiErr.IsZero() {
		log.WithField("error_code", apiErr.Code).WithField("error_type", apiErr.Error).Debug("Error checking scopes")
		if granter.Redirects() {
			s.redirectError(w, r, apiErr, redirectURI)
			return
		}
		s.renderError(w, r, apiErr)
		return
	}

	log = log.WithField("scopes_filtered", checkedScopes)

	// retrieve or fill out our grant fields
	grant := granter.Grant(yall.InContext(r.Context(), log), checkedScopes)

	// create and store our grant for granters
	// that don't create their own
	if granter.CreatesGrantsInline() {
		// build our grant
		grant.CreateIP = getIP(r)

		// store the grant
		grant, apiErr = s.createGrant(yall.InContext(r.Context(), log), grant)
		if !apiErr.IsZero() {
			log.WithField("error_code", apiErr.Code).WithField("error_type", apiErr.Error).Debug("Error creating grant")
			if granter.Redirects() {
				s.redirectError(w, r, apiErr, redirectURI)
				return
			}
			s.renderError(w, r, apiErr)
			return
		}
		log = log.WithField("grant", grant.ID)
		log.Debug("created inline grant")
	} else {
		log = log.WithField("grant", grant.ID)
	}

	grant, err = s.Grants.Storer.ExchangeGrant(yall.InContext(r.Context(), log), grants.GrantUse{
		Grant: grant.ID,
		IP:    getIP(r),
		Time:  time.Now(),
	})

	if errors.Is(err, grants.ErrGrantAlreadyUsed) || errors.Is(err, grants.ErrGrantNotFound) { //nolint: nestif // I don't know how to make this simpler easily.
		if errors.Is(err, grants.ErrGrantAlreadyUsed) {
			log.Debug("grant reuse attempted")
		} else {
			log.Debug("unknown grant presented")
		}
		if granter.Redirects() {
			s.redirectError(w, r, APIError{Code: http.StatusBadRequest, Error: "invalid_grant"}, redirectURI)
			return
		}
		s.renderError(w, r, APIError{Code: http.StatusBadRequest, Error: "invalid_grant"})
		return
	} else if err != nil {
		log.WithError(err).Error("error exchanging grant")
		if granter.Redirects() {
			s.redirectError(w, r, serverError, redirectURI)
			return
		}
		s.renderError(w, r, serverError)
		return
	}

	log.Debug("exchanged grant")

	// issue tokens using the grant
	token, apiErr := s.issueTokens(yall.InContext(r.Context(), log), grant)
	if !apiErr.IsZero() {
		log.WithField("error_code", apiErr.Code).WithField("error_type", apiErr.Error).Debug("Error issuing tokens")
		if granter.Redirects() {
			s.redirectError(w, r, apiErr, redirectURI)
			return
		}
		s.renderError(w, r, apiErr)
		return
	}

	log.Debug("issued tokens")

	// call any functionality that we need to to mark the grant as used
	err = granter.Granted(yall.InContext(r.Context(), log))
	if err != nil {
		log.WithError(err).Error("Error marking grant as used")
	}

	log.Debug("marked grant as used")

	// return our tokens
	if granter.Redirects() {
		s.redirectToken(w, r, token, redirectURI)
		return
	}
	s.renderToken(w, r, token)
}

// handle the grant request endpoint
// this endpoint is used when the user wants to to start the authorization
// process, to generate a Grant that can be redeemed for a token.
func (s Service) handleGrantRequest(w http.ResponseWriter, r *http.Request) {
	log := yall.FromContext(r.Context())

	// check our content-type. r.ParseForm() only works if the header is
	// set to application/x-www-form-urlencoded
	if !isContentType(r.Context(), r, "application/x-www-form-urlencoded") {
		log.WithField("content_type", r.Header.Get("Content-Type")).Debug("invalid content type")
		s.renderError(w, r, APIError{
			Error: "unsupported_content_type",
			Code:  http.StatusUnsupportedMediaType,
		})
		return
	}

	// explicitly parse the form, so we can handle the error
	err := r.ParseForm()
	if err != nil {
		log.WithError(err).Error("Error parsing form")
		s.renderError(w, r, invalidRequestError)
		return
	}

	// figure out which client we're dealing with
	clientID, clientSecret, redirectURI := getClientCredentials(r)
	log = log.WithField("oauth2_client_id", clientID).WithField("redirect_uri_given", redirectURI)

	// make sure the client is who they say they are
	clientErr := s.validateClientCredentials(yall.InContext(r.Context(), log), clientID, clientSecret, redirectURI)
	if !clientErr.IsZero() {
		log.WithField("api_error", clientErr).Debug("Error validating client")
		s.renderError(w, r, clientErr)
		return
	}

	log = log.WithField("response_type", r.PostForm.Get("response_type"))

	// figure out what type of grant the user is requesting
	grantCreator := s.getGrantCreator(r.PostForm, clientID)
	if grantCreator == nil {
		// if g is nil, that means it's not a match for our supported types
		log.Debug("Unsupported response type")
		s.renderError(w, r, APIError{
			Error: "unsupported_response_type",
			Code:  http.StatusBadRequest,
		})
		return
	}

	// figure out which redirect URI to use for our client
	redirectURI, err = s.getClientRedirectURI(yall.InContext(r.Context(), log), clientID, redirectURI)
	if err != nil {
		log.WithError(err).Error("Error determining redirect URI.")
		s.renderError(w, r, serverError)
		return
	}
	log = log.WithField("redirect_uri", redirectURI)

	// get the account we're creating a grant for
	account, apiErr := grantCreator.GetAccount(yall.InContext(r.Context(), log))
	if !apiErr.IsZero() {
		log.WithField("error_code", apiErr.Code).WithField("error_type", apiErr.Error).Debug("error getting account")
		if grantCreator.ResponseMethod() == rmRedirect {
			s.redirectError(w, r, apiErr, redirectURI)
			return
		}
		s.renderError(w, r, apiErr)
		return
	}

	// figure out what scopes we should be using
	var requestedScopes []string
	for _, scope := range strings.Split(r.FormValue("scope"), " ") {
		if strings.TrimSpace(scope) != "" {
			requestedScopes = append(requestedScopes, strings.TrimSpace(scope))
		}
	}
	log = log.WithField("scopes_requested", requestedScopes)
	checkedScopes, apiErr := s.checkScopes(yall.InContext(r.Context(), log), clientID, account.ProfileID, account.ID, requestedScopes)
	if !apiErr.IsZero() {
		log.WithField("error_code", apiErr.Code).WithField("error_type", apiErr.Error).Debug("Error checking scopes")
		if grantCreator.ResponseMethod() == rmRedirect {
			s.redirectError(w, r, apiErr, redirectURI)
			return
		}
		s.renderError(w, r, apiErr)
		return
	}

	log = log.WithField("scopes_filtered", checkedScopes)

	// fill out our grant fields
	grant, apiErr := grantCreator.FillGrant(yall.InContext(r.Context(), log), account, checkedScopes)
	if !apiErr.IsZero() {
		if grantCreator.ResponseMethod() == rmRedirect {
			s.redirectError(w, r, apiErr, redirectURI)
			return
		}
		s.renderError(w, r, apiErr)
		return
	}
	grant.CreateIP = getIP(r)

	// store the grant
	grant, apiErr = s.createGrant(yall.InContext(r.Context(), log), grant)
	if !apiErr.IsZero() {
		log.WithField("error_code", apiErr.Code).WithField("error_type", apiErr.Error).Debug("Error creating grant")
		if grantCreator.ResponseMethod() == rmRedirect {
			s.redirectError(w, r, apiErr, redirectURI)
			return
		}
		s.renderError(w, r, apiErr)
		return
	}
	log = log.WithField("grant", grant.ID)
	log.Debug("created grant")

	if grantCreator.ResponseMethod() == rmOOB {
		err = grantCreator.HandleOOBGrant(yall.InContext(r.Context(), log), grant)
		if err != nil {
			log.WithError(err).Error("Error handling OOB grant")
			s.renderError(w, r, serverError)
			return
		}
		// fall through, s.returnGrant will write the correct status
		// code for us and handle this situation correctly.
	}

	// return the grant
	switch grantCreator.ResponseMethod() {
	case rmOOB:
		s.returnGrantOOB(w)
	case rmRedirect:
		s.redirectGrant(w, r, grant, redirectURI)
	default:
		log.WithField("response_method", grantCreator.ResponseMethod()).Error("unrecognized response_method")
		s.renderError(w, r, serverError)
	}
}
