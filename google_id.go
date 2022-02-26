package oauth2

import (
	"context"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"impractical.co/googleid"
	yall "yall.in"

	"lockbox.dev/accounts"
	"lockbox.dev/grants"
)

// googleIDGranter fills the granter interface for exchanging
// a Google ID token for a Grant.
type googleIDGranter struct {
	tokenVal     string                // the token
	client       string                // the client that created the token
	gClients     []string              // the Google clients that the token must be for
	oidcVerifier *oidc.IDTokenVerifier // the verifier that we can use to verify tokens
	accounts     accounts.Storer       // the Storer that grants access to accounts data

	// set by Validate and here so Grant can use them
	account accounts.Account
	token   *googleid.Token
}

// Validate checks that the ID token is actually valid and should
// be considered proof of identity.
func (g *googleIDGranter) Validate(ctx context.Context) APIError {
	token, err := googleid.Decode(g.tokenVal)
	if err != nil {
		yall.FromContext(ctx).WithError(err).Debug("Error decoding ID token")
		return invalidGrantError
	}
	err = googleid.Verify(ctx, g.tokenVal, g.gClients, g.oidcVerifier)
	if err != nil {
		yall.FromContext(ctx).WithError(err).Debug("Error verifying ID token")
		return invalidGrantError
	}
	g.token = token
	account, err := g.accounts.Get(ctx, strings.ToLower(token.Email))
	if err != nil {
		yall.FromContext(ctx).WithError(err).WithField("email", token.Email).Error("Error retriving account")
		return serverError
	}
	g.account = account
	return APIError{}
}

// ProfileID returns the ID of the profile the grant is for. It must be called
// after Validate.
func (g *googleIDGranter) ProfileID(ctx context.Context) string {
	return g.account.ProfileID
}

// AccountID returns the ID of the account the grant is for. It must be called
// after Validate.
func (g *googleIDGranter) AccountID(ctx context.Context) string {
	return g.account.ID
}

// Grant returns a Grant populated with the appropriate values for
// a Google ID Token-generated Grant.
func (g *googleIDGranter) Grant(ctx context.Context, scopes []string) grants.Grant {
	return grants.Grant{
		SourceType: "google_id",
		SourceID:   g.token.Iss + ";" + g.token.Sub + ";" + strconv.FormatInt(g.token.Iat, 10),
		AccountID:  g.account.ID,
		ProfileID:  g.account.ProfileID,
		ClientID:   g.client,
		Scopes:     scopes,
		Used:       false,
	}
}

// Granted does nothing, we rely on SourceID to keep from issuing
// duplicate grants for the same token.
func (g *googleIDGranter) Granted(ctx context.Context) error {
	return nil
}

// Redirects returns false, indicating we want to use the JSON request/response
// flow, not the URL querystring redirect flow.
func (g *googleIDGranter) Redirects() bool {
	return false
}

func (g *googleIDGranter) CreatesGrantsInline() bool {
	return true
}
