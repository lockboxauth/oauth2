package oauth2

import (
	"context"
	"errors"
	"strings"

	yall "yall.in"

	"lockbox.dev/grants"
	"lockbox.dev/tokens"
)

// issueTokens creates an access token and a refresh token based on the grant
// passed.
func (s Service) issueTokens(ctx context.Context, grant grants.Grant) (Token, APIError) {
	// generate access first, so if there's a problem
	// the refresh token isn't just floating around, unused
	access, err := s.IssueAccessToken(ctx, grant)
	if err != nil {
		yall.FromContext(ctx).WithError(err).Error("Error generating access token")
		return Token{}, serverError
	}

	refresh, err := s.IssueRefreshToken(ctx, grant)
	if err != nil {
		yall.FromContext(ctx).WithError(err).Error("Error issuing refresh token")
		return Token{}, serverError
	}
	return Token{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    s.TokenExpiresIn,
		RefreshToken: refresh,
		Scope:        strings.Join(grant.Scopes, ","),
	}, APIError{}
}

type refreshTokenGranter struct {
	tokenVal string
	token    tokens.RefreshToken
	client   string
	deps     Service
}

// Validate checks that the tokenVal and client associated with
// the refreshTokenGranter are valid and should be tradeable for
// a grant.
func (r *refreshTokenGranter) Validate(ctx context.Context) APIError {
	token, err := r.deps.ValidateRefreshToken(ctx, r.tokenVal, r.client)
	if err != nil {
		if errors.Is(err, tokens.ErrInvalidToken) {
			return invalidGrantError
		}
		r.deps.Log.WithError(err).Error("Error validating refresh token")
		return serverError
	}
	r.token = token
	return APIError{}
}

// ProfileID returns the ID of the profile the grant is for. It must be called
// after Validate.
func (r *refreshTokenGranter) ProfileID(_ context.Context) string {
	return r.token.ProfileID
}

// AccountID returns the ID of the account the grant is for. It must be called
// after Validate.
func (r *refreshTokenGranter) AccountID(_ context.Context) string {
	return r.token.AccountID
}

// Grant returns a Grant with the values populated as appropriate
// for a grant generated from a refresh token.
func (r *refreshTokenGranter) Grant(_ context.Context, requestedScopes []string) grants.Grant {
	return grants.Grant{
		SourceType: "refresh_token",
		SourceID:   r.token.ID,
		Scopes:     requestedScopes,
		AccountID:  r.token.AccountID,
		ProfileID:  r.token.ProfileID,
		ClientID:   r.token.ClientID,
		Used:       false,
	}
}

// Granted marks a refresh token as used, so it can't be reused.
func (r *refreshTokenGranter) Granted(ctx context.Context) error {
	return r.deps.UseRefreshToken(ctx, r.token.ID)
}

// Redirects returns false, indicating that when using this
// grant type, we want the JSON request/response flow, not
// the URL querystring redirect flow.
func (*refreshTokenGranter) Redirects() bool {
	return false
}

// CreatesGrantsInline reports that `refreshTokenGranter` creates its grants as
// part of the token endpoint, without needing to call the authorize endpoint
// first.
func (*refreshTokenGranter) CreatesGrantsInline() bool {
	return true
}
