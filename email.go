package oauth2

import (
	"context"
	"encoding/base64"

	uuid "github.com/hashicorp/go-uuid"
	yall "yall.in"

	"lockbox.dev/accounts"
	"lockbox.dev/grants"
)

type emailer interface {
	SendMail(ctx context.Context, email, code string) error
}

// emailGranter fills the granter interface for handling a Grant passed
// by its ID. The expectation is that the user will request a Grant be
// emailed to them as a link, they'll click the link, and end that link
// will exchange the Grant for a session.
type emailGranter struct {
	code     string // the code presented as proof of grant
	clientID string // the clientID using the Grant
	grants   grants.Storer

	// populated in Validate
	grant grants.Grant // the Grant being traded for a session
}

// Validate retrieves the Grant and stores it for later reference,
// ensuring that it is valid and authorized.
func (g *emailGranter) Validate(ctx context.Context) APIError {
	log := yall.FromContext(ctx)
	log = log.WithField("passed_code", g.code)
	grant, err := g.grants.GetGrantBySource(ctx, "email", g.code)
	if err != nil {
		if err == grants.ErrGrantNotFound {
			log.Debug("grant not found")
			return invalidRequestError
		}
		log.WithError(err).Error("error retrieving grant")
		return serverError
	}
	g.grant = grant
	return APIError{}
}

// Grant returns the grant we retrieved in Validate.
func (g *emailGranter) Grant(ctx context.Context, scopes []string) grants.Grant {
	return g.grant
}

// Granted does nothing, the Grant will automatically be marked as used
// when it is exchanged for a session.
func (g *emailGranter) Granted(ctx context.Context) error {
	return nil
}

// Redirects returns false, indicating we want to use the JSON request/response
// flow, not the URL querystring redirect flow.
func (g *emailGranter) Redirects() bool {
	return false
}

// CreatesGrantsInline returns false, indicating we don't want the access token
// exchange to generate a new Grant, we just want to use a previously generated
// Grant.
func (g *emailGranter) CreatesGrantsInline() bool {
	return false
}

type emailGrantCreator struct {
	email    string
	client   string
	accounts accounts.Storer
	emailer  emailer
}

func (g *emailGrantCreator) FillGrant(ctx context.Context, scopes []string) (grants.Grant, APIError) {
	log := yall.FromContext(ctx)
	account, err := g.accounts.Get(ctx, g.email)
	if err != nil {
		if err == accounts.ErrAccountNotFound {
			log.WithField("email", g.email).Debug("account not found")
			return grants.Grant{}, invalidRequestError
		}
		log.WithError(err).Error("error retrieving account")
		return grants.Grant{}, serverError
	}
	codeBytes, err := uuid.GenerateRandomBytes(32)
	if err != nil {
		log.WithError(err).Error("error generating random bytes")
		return grants.Grant{}, serverError
	}
	return grants.Grant{
		SourceType: "email",
		SourceID:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(codeBytes),
		Scopes:     scopes,
		AccountID:  account.ID,
		ProfileID:  account.ProfileID,
		ClientID:   g.client,
	}, APIError{}
}

func (g *emailGrantCreator) ResponseMethod() responseMethod {
	return rmOOB
}

func (g *emailGrantCreator) HandleOOBGrant(ctx context.Context, grant grants.Grant) error {
	log := yall.FromContext(ctx)
	err := g.emailer.SendMail(ctx, g.email, grant.SourceID)
	if err != nil {
		log.WithError(err).Debug("Error sending mail")
		return err
	}
	return nil
}
