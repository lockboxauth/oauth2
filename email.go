package oauth2

import (
	"context"
	"encoding/base64"
	"errors"

	uuid "github.com/hashicorp/go-uuid"
	yall "yall.in"

	"lockbox.dev/accounts"
	"lockbox.dev/grants"
)

type emailer interface {
	SendMail(ctx context.Context, email, code string) error
}

// MemoryEmailer is an in-memory implementation of the `emailer` interface that
// simply tracks the last code sent and the email it was "sent" to.
//
// Its intended use is in testing.
type MemoryEmailer struct {
	LastCode  string
	LastEmail string
}

// SendMail records the passed code and email in the `MemoryEmailer` for later
// retrieval. It never returns an error.
func (m *MemoryEmailer) SendMail(_ context.Context, email, code string) error {
	m.LastCode = code
	m.LastEmail = email
	return nil
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
		if errors.Is(err, grants.ErrGrantNotFound) {
			log.Debug("grant not found")
			return invalidRequestError
		}
		log.WithError(err).Error("error retrieving grant")
		return serverError
	}
	g.grant = grant
	return APIError{}
}

// ProfileID returns the ID of the profile the grant is for. It must be called
// after Validate.
func (g *emailGranter) ProfileID(_ context.Context) string {
	return g.grant.ProfileID
}

// AccountID returns the ID of the account the grant is for. It must be called
// after Validate.
func (g *emailGranter) AccountID(_ context.Context) string {
	return g.grant.AccountID
}

// Grant returns the grant we retrieved in Validate.
func (g *emailGranter) Grant(_ context.Context, _ []string) grants.Grant {
	return g.grant
}

// Granted does nothing, the Grant will automatically be marked as used
// when it is exchanged for a session.
func (*emailGranter) Granted(_ context.Context) error {
	return nil
}

// Redirects returns false, indicating we want to use the JSON request/response
// flow, not the URL querystring redirect flow.
func (*emailGranter) Redirects() bool {
	return false
}

// CreatesGrantsInline returns false, indicating we don't want the access token
// exchange to generate a new Grant, we just want to use a previously generated
// Grant.
func (*emailGranter) CreatesGrantsInline() bool {
	return false
}

type emailGrantCreator struct {
	email    string
	client   string
	accounts accounts.Storer
	emailer  emailer
}

// GetAccount returns the `accounts.Account` associated with `g.email`. The
// APIError returned is intended to be rendered, not inspected.
func (g *emailGrantCreator) GetAccount(ctx context.Context) (accounts.Account, APIError) {
	log := yall.FromContext(ctx)
	account, err := g.accounts.Get(ctx, g.email)
	if err != nil {
		if errors.Is(err, accounts.ErrAccountNotFound) {
			log.WithField("email", g.email).Debug("account not found")
			return accounts.Account{}, invalidRequestError
		}
		log.WithError(err).Error("error retrieving account")
		return accounts.Account{}, serverError
	}
	return account, APIError{}
}

// FillGrant creates a new `grants.Grant` with a `SourceType` of "email". The
// `SourceID` is a randomly generated URL-safe-base64-encoded string.
func (g *emailGrantCreator) FillGrant(ctx context.Context, account accounts.Account, scopes []string) (grants.Grant, APIError) {
	log := yall.FromContext(ctx)
	numCodeBytes := 32
	codeBytes, err := uuid.GenerateRandomBytes(numCodeBytes)
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

// ResponseMethod reports that emailGrantCreator responses should be sent out
// of band, not through redirect or returning them in the response.
func (*emailGrantCreator) ResponseMethod() responseMethod {
	return rmOOB
}

// HandleOOBGrant sends the email containing the `grants.Grant` code that can
// be exchanged at the token endpoint for an access token.
func (g *emailGrantCreator) HandleOOBGrant(ctx context.Context, grant grants.Grant) error {
	log := yall.FromContext(ctx)
	err := g.emailer.SendMail(ctx, g.email, grant.SourceID)
	if err != nil {
		log.WithError(err).Debug("Error sending mail")
		return err
	}
	return nil
}
