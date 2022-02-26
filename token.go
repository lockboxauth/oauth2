package oauth2

import (
	"context"
	"errors"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	yall "yall.in"

	"lockbox.dev/grants"
	"lockbox.dev/sessions"
	"lockbox.dev/tokens"
)

// Token is an OAuth2-style token response.
type Token struct {
	AccessToken  string `json:"access_token"`            //nolint:tagliatelle // look, talk to the OAuth2 spec
	TokenType    string `json:"token_type"`              //nolint:tagliatelle // look, talk to the OAuth2 spec
	ExpiresIn    int    `json:"expires_in,omitempty"`    //nolint:tagliatelle // look, talk to the OAuth2 spec
	RefreshToken string `json:"refresh_token,omitempty"` //nolint:tagliatelle // look, talk to the OAuth2 spec
	Scope        string `json:"scope,omitempty"`         //nolint:tagliatelle // look, talk to the OAuth2 spec
}

// IssueRefreshToken creates a Refresh Token and stores it in the service indicated by
// `Refresh` on `s`. It fills the token with the appropriate values from `grant`, sets
// any unset defaults, and stores the token before returning it.
func (s Service) IssueRefreshToken(ctx context.Context, grant grants.Grant) (string, error) {
	refresh, err := tokens.FillTokenDefaults(tokens.RefreshToken{
		CreatedFrom: grant.ID,
		Scopes:      grant.Scopes,
		ProfileID:   grant.ProfileID,
		AccountID:   grant.AccountID,
		ClientID:    grant.ClientID,
	})
	if err != nil {
		return "", err
	}
	token, err := s.Refresh.CreateJWT(ctx, refresh)
	if err != nil {
		return "", err
	}
	err = s.Refresh.Storer.CreateToken(ctx, refresh)
	if err != nil {
		return "", err
	}
	return token, nil
}

// ValidateRefreshToken verifies that a refresh token is valid and for the specified
// client, returning the struct representation of valid tokens.
func (s Service) ValidateRefreshToken(ctx context.Context, token, client string) (tokens.RefreshToken, error) {
	tok, err := s.Refresh.Validate(ctx, token)
	if err != nil {
		return tokens.RefreshToken{}, err
	}
	if tok.ClientID != client {
		yall.FromContext(ctx).WithField("client_id", client).WithField("desired_id", tok.ClientID).Debug("Client tried to use other client's refresh token.")
		return tokens.RefreshToken{}, tokens.ErrInvalidToken
	}
	return tok, nil
}

// UseRefreshToken marks a refresh token as used, making it so the token cannot be
// reused.
func (s Service) UseRefreshToken(ctx context.Context, tokenID string) error {
	err := s.Refresh.Storer.UseToken(ctx, tokenID)
	if err != nil && !errors.Is(err, tokens.ErrTokenUsed) {
		yall.FromContext(ctx).WithField("token", tokenID).WithError(err).Error("Error using token.")
		return err
	}
	if errors.Is(err, tokens.ErrTokenUsed) {
		return err
	}
	return nil
}

// IssueAccessToken creates a new access token from a Grant, filling in the values
// appropriately.
func (s Service) IssueAccessToken(ctx context.Context, grant grants.Grant) (string, error) {
	id, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}
	return s.Sessions.CreateJWT(ctx, sessions.AccessToken{
		ID:          id,
		CreatedFrom: grant.ID,
		Scopes:      grant.Scopes,
		ProfileID:   grant.ProfileID,
		ClientID:    grant.ClientID,
		CreatedAt:   time.Now(),
	})
}
