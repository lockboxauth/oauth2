package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/pkg/errors"
	yall "yall.in"

	"lockbox.dev/accounts"
	"lockbox.dev/grants"
)

const (
	emailLength = 1 * time.Hour
)

// emailGranter fills the granter interface for handling a Grant passed
// as a JWT. The expectation is that the user will request a Grant be
// emailed to them as a link, they'll click the link, and end that link
// will exchange the Grant for a session.
type emailGranter struct {
	jwtSigner

	jwt      string // the JWT passed in
	clientID string // the clientID using the Grant

	// populated in Validate
	grant grants.Grant // the Grant being traded for a session
}

// Validate parses the passed JWT and stores it for later reference,
// ensuring that it is a valid and authorized JWT.
func (g *emailGranter) Validate(ctx context.Context) APIError {
	tok, err := jwt.ParseWithClaims(g.jwt, &codeClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		fp, err := g.getPublicKeyFingerprint()
		if err != nil {
			return nil, err
		}
		if fp != token.Header["kid"] {
			return nil, errors.New("unknown signing key")
		}
		return g.jwtSigner.publicKey, nil
	})
	if err != nil {
		yall.FromContext(ctx).WithError(err).Debug("Error validating token.")
		return invalidRequestError
	}
	claims, ok := tok.Claims.(*codeClaims)
	if !ok {
		return serverError
	}
	if claims.Audience != g.clientID {
		return invalidRequestError
	}
	g.grant = grants.Grant{
		ID:         claims.Id,
		SourceType: claims.SourceType,
		SourceID:   claims.SourceID,
		CreatedAt:  time.Unix(claims.IssuedAt, 0),
		Scopes:     claims.Scopes,
		ProfileID:  claims.Subject,
		ClientID:   claims.Audience,
		CreateIP:   claims.CreateIP,
	}
	return APIError{}
}

// Grant returns the parsed JWT as a grants.Grant.
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

type emailer interface {
	SendMail(ctx context.Context, email, code string) error
}

type emailGrantCreator struct {
	jwtSigner

	email     string
	client    string
	accounts  accounts.Storer
	emailer   emailer
	serviceID string
}

type codeClaims struct {
	jwt.StandardClaims
	Scopes     []string `json:"scopes,omitempty"`
	SourceType string   `json:"source_type,omitempty"`
	SourceID   string   `json:"source_id,omitempty"`
	CreateIP   string   `json:"create_ip,omitempty"`
}

func (g *emailGrantCreator) FillGrant(ctx context.Context, scopes []string) (grants.Grant, APIError) {
	account, err := g.accounts.Get(ctx, g.email)
	if err != nil {
		if err == accounts.ErrAccountNotFound {
			return grants.Grant{}, invalidRequestError
		}
		return grants.Grant{}, serverError
	}
	u, err := uuid.GenerateUUID()
	if err != nil {
		return grants.Grant{}, serverError
	}
	return grants.Grant{
		SourceType: "email",
		SourceID:   hex.EncodeToString(sha256.New().Sum([]byte(g.email + "," + u))),
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
	codeData := jwt.NewWithClaims(jwt.SigningMethodRS256, codeClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  grant.ClientID,
			ExpiresAt: grant.CreatedAt.UTC().Add(emailLength).Unix(),
			Id:        grant.ID,
			IssuedAt:  grant.CreatedAt.UTC().Unix(),
			Issuer:    g.serviceID,
			NotBefore: grant.CreatedAt.UTC().Add(-1 * time.Hour).Unix(),
			Subject:   grant.ProfileID,
		},
		Scopes:     grant.Scopes,
		SourceType: grant.SourceType,
		SourceID:   grant.SourceID,
		CreateIP:   grant.CreateIP,
	})
	fp, err := g.getPublicKeyFingerprint()
	if err != nil {
		return err
	}
	codeData.Header["kid"] = fp
	log = log.WithField("jwt_kid", fp)
	code, err := codeData.SignedString(g.jwtSigner.privateKey)
	if err != nil {
		return err
	}
	err = g.emailer.SendMail(ctx, g.email, code)
	if err != nil {
		return err
	}
	return nil
}
