package oauth2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"lockbox.dev/accounts"
	accountsMemory "lockbox.dev/accounts/storers/memory"
	"lockbox.dev/clients"
	clientsMemory "lockbox.dev/clients/storers/memory"
	"lockbox.dev/grants"
	grantsMemory "lockbox.dev/grants/storers/memory"
	"lockbox.dev/scopes"
	scopesMemory "lockbox.dev/scopes/storers/memory"
	"lockbox.dev/sessions"
	"lockbox.dev/tokens"
	tokensMemory "lockbox.dev/tokens/storers/memory"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/nsf/jsondiff"
	yall "yall.in"
	testLogger "yall.in/testing"
)

func uuidOrFail(t *testing.T) string {
	t.Helper()

	id, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("Unexpected error generating ID: %s", err.Error())
	}
	return id
}

func TestCreateGrantFromEmail(t *testing.T) {
	t.Parallel()

	change, err := clients.ChangeSecret([]byte("testing"))
	if err != nil {
		t.Fatalf("error generating secret hash: %v", err)
	}

	secretHash := *change.SecretHash
	secretScheme := *change.SecretScheme

	type testCase struct {
		// fixtures to include prior to the request being made
		existingAccounts []accounts.Account
		existingClients  []clients.Client
		existingScopes   []scopes.Scope

		// body of the request to send
		body string

		// headers of the request to send
		headers http.Header

		// URL query parameters to append to the default path
		params url.Values

		// override the default POST method if set
		overrideMethod string

		// override the entire path, including params, if set
		overridePath string

		// expected HTTP status code
		expectedStatus int

		// expected body
		expectedBody string

		// email the code is expected to get sent to, leave empty
		// if no code is expected to be sent
		expectedEmail string

		// set to true if a code is expected to be set, false if not
		expectedCode bool

		// the scopes that are expected on the created grant, if
		// expectedCode is true
		expectedScopes []string

		// the profileID expected for the created grant, if
		// expectedCode is true
		expectedProfileID string

		// the accountID expected for the created grant, if
		// expectedCode is true
		expectedAccountID string

		// the client ID expected for the created grant, if
		// expectedCode is true
		expectedClientID string
	}

	tests := map[string]testCase{
		// test the case where a user has already registered and is
		// logging in
		"happy-path": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 204,
			expectedEmail:  "test@lockbox.dev",
			expectedCode:   true,
			expectedScopes: []string{
				"https://scopes.lockbox.dev/testing/default",
				"https://scopes.lockbox.dev/testing/default2",
			},
			expectedAccountID: "test@lockbox.dev",
			expectedProfileID: "testing123",
			expectedClientID:  "testclient",
		},

		// test a request that doesn't specify a Content-Type header,
		// which we should explicitly reject because requests without
		// Content-Type headers means the net/http library won't parse
		// the body and that leads to all sorts of weirdness, so we
		// should just explicitly reject them
		"no-content-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
			},
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedBody:   `{"error": "unsupported_content_type"}`,
		},

		// test a request that specifies an unsupported Content-Type
		// header which we should explicitly reject because requests
		// with Content-Type headers set to anything but
		// application/x-www-form-urlencoded means the net/http library
		// won't parse the body and that leads to all sorts of
		// weirdness, so we should just explicitly reject them
		"unsupported-content-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: `{"response_type": "email", "email": "test@lockbox.dev"}`,
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/json"},
			},
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedBody:   `{"error": "unsupported_content_type"}`,
		},

		// test a request to log in as a user that doesn't exist
		"unregistered-user": {
			existingAccounts: []accounts.Account{},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "invalid_request"}`,
		},

		// test a request that's missing the email parameter
		"no-email": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: "response_type=email",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "invalid_request"}`,
		},

		// test a request that doesn't have any client credentials
		// specified
		"no-client-credentials": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error": "invalid_client"}`,
		},

		// test setting the client credentials in the basic auth header
		"basic-auth-client-credentials": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 204,
			expectedEmail:  "test@lockbox.dev",
			expectedCode:   true,
			expectedScopes: []string{
				"https://scopes.lockbox.dev/testing/default",
				"https://scopes.lockbox.dev/testing/default2",
			},
			expectedAccountID: "test@lockbox.dev",
			expectedProfileID: "testing123",
			expectedClientID:  "testclient",
		},

		// test setting the client credentials in the request body
		"request-body-client-credentials": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev&client_id=testclient&client_secret=testing",
			headers: map[string][]string{
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 204,
			expectedEmail:  "test@lockbox.dev",
			expectedCode:   true,
			expectedScopes: []string{
				"https://scopes.lockbox.dev/testing/default",
				"https://scopes.lockbox.dev/testing/default2",
			},
			expectedAccountID: "test@lockbox.dev",
			expectedProfileID: "testing123",
			expectedClientID:  "testclient",
		},

		// test a client ID that doesn't correspond to an actual client
		"nonexistent-client": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("fakeclient:testing123")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 401,
			expectedBody:   `{"error": "invalid_client"}`,
		},

		// test using the wrong client secret
		"wrong-client-secret": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing1234")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 401,
			expectedBody:   `{"error": "invalid_client"}`,
		},

		// test requesting scopes explicitly instead of using the
		// defaults
		"non-default-scopes": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev&scope=https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fdefault%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fnot-default",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 204,
			expectedEmail:  "test@lockbox.dev",
			expectedCode:   true,
			expectedScopes: []string{
				"https://scopes.lockbox.dev/testing/default",
				"https://scopes.lockbox.dev/testing/not-default",
			},
			expectedAccountID: "test@lockbox.dev",
			expectedProfileID: "testing123",
			expectedClientID:  "testclient",
		},

		// test requesting scopes that the client can't use
		// the request should succeed, but those scopes shouldn't be
		// included in the grant that's returned
		"strip-unauthorized-client-scopes": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:               "https://scopes.lockbox.dev/testing/included",
					UserPolicy:       scopes.PolicyAllowAll,
					ClientPolicy:     scopes.PolicyDefaultDeny,
					ClientExceptions: []string{"testclient"},
				},
				{
					ID:               "https://scopes.lockbox.dev/testing/not-included",
					UserPolicy:       scopes.PolicyAllowAll,
					ClientPolicy:     scopes.PolicyDefaultDeny,
					ClientExceptions: []string{"nottherightclient"},
				},
				{
					ID:               "https://scopes.lockbox.dev/testing/excluded",
					UserPolicy:       scopes.PolicyAllowAll,
					ClientPolicy:     scopes.PolicyDefaultAllow,
					ClientExceptions: []string{"testclient"},
				},
				{
					ID:               "https://scopes.lockbox.dev/testing/not-excluded",
					UserPolicy:       scopes.PolicyAllowAll,
					ClientPolicy:     scopes.PolicyDefaultAllow,
					ClientExceptions: []string{"someotherclient"},
				},
			},
			body: "response_type=email&email=test@lockbox.dev&scope=https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fdefault%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fincluded%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fnot-included%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fexcluded%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fnot-excluded",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 204,
			expectedEmail:  "test@lockbox.dev",
			expectedCode:   true,
			expectedScopes: []string{
				"https://scopes.lockbox.dev/testing/default",
				"https://scopes.lockbox.dev/testing/included",
				"https://scopes.lockbox.dev/testing/not-excluded",
			},
			expectedAccountID: "test@lockbox.dev",
			expectedProfileID: "testing123",
			expectedClientID:  "testclient",
		},

		// test requesting scopes that the user can't use
		// the request should succeed, but those scopes shouldn't be
		// included in the grant that's returned
		"strip-unauthorized-user-scopes": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:             "https://scopes.lockbox.dev/testing/included",
					UserPolicy:     scopes.PolicyDefaultDeny,
					UserExceptions: []string{"test@lockbox.dev"},
					ClientPolicy:   scopes.PolicyAllowAll,
				},
				{
					ID:             "https://scopes.lockbox.dev/testing/not-included",
					UserPolicy:     scopes.PolicyDefaultDeny,
					UserExceptions: []string{"nottherightuser@lockbox.dev"},
					ClientPolicy:   scopes.PolicyAllowAll,
				},
				{
					ID:             "https://scopes.lockbox.dev/testing/excluded",
					UserPolicy:     scopes.PolicyDefaultAllow,
					UserExceptions: []string{"test@lockbox.dev"},
					ClientPolicy:   scopes.PolicyAllowAll,
				},
				{
					ID:             "https://scopes.lockbox.dev/testing/not-excluded",
					UserPolicy:     scopes.PolicyDefaultAllow,
					UserExceptions: []string{"someotheruser@lockbox.dev"},
					ClientPolicy:   scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev&scope=https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fdefault%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fincluded%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fnot-included%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fexcluded%20https%3A%2F%2Fscopes.lockbox.dev%2Ftesting%2Fnot-excluded",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 204,
			expectedEmail:  "test@lockbox.dev",
			expectedCode:   true,
			expectedScopes: []string{
				"https://scopes.lockbox.dev/testing/default",
				"https://scopes.lockbox.dev/testing/included",
				"https://scopes.lockbox.dev/testing/not-excluded",
			},
			expectedAccountID: "test@lockbox.dev",
			expectedProfileID: "testing123",
			expectedClientID:  "testclient",
		},

		// test a request that's got an unparseable body
		"unparseable": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: "response_type;",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "invalid_request"}`,
		},

		// test a request that's missing the response_type
		"no-response-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: "email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "unsupported_response_type"}`,
		},

		// test an invalid response_type
		"invalid-response-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: "response_type=email2&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "unsupported_response_type"}`,
		},
		// TODO: test an error getting a redirect URI
		// TODO: test an error checking scopes
		// TODO: test an error filling the grant
		// TODO: test an error creating the grant
		// TODO: test an error handling OOB grants
		// TODO: test a redirect grant
		// TODO: test an invalid grantCreator.ResponseMethod()
	}

	codeRE, err := regexp.Compile("^(?:[A-Za-z0-9-_]{4})*(?:[A-Za-z0-9-_]{2}|[A-Za-z0-9-_]{3})?$")
	if err != nil {
		t.Fatalf("Error compiling regular expression for emailed codes: %s", err)
	}

	for name, testCase := range tests {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
			if logLevel == "" {
				logLevel = "ERROR"
			}
			logger := yall.New(testLogger.New(t, yall.Severity(logLevel)))

			params := url.Values{}
			if testCase.params != nil {
				for k, v := range testCase.params {
					params[k] = append(params[k], v...)
				}
			}
			requestPath := "/authorize?" + params.Encode()
			if testCase.overridePath != "" {
				requestPath = testCase.overridePath
			}
			method := http.MethodPost
			if testCase.overrideMethod != "" {
				method = testCase.overrideMethod
			}
			req := httptest.NewRequest(method, requestPath, bytes.NewBuffer([]byte(testCase.body)))
			req.Header = testCase.headers
			req = req.WithContext(yall.InContext(req.Context(), logger))
			respRec := httptest.NewRecorder()
			acctsStorer, err := accountsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for accounts: %s", err)
			}
			for _, acct := range testCase.existingAccounts {
				err = acctsStorer.Create(context.Background(), acct)
				if err != nil {
					t.Fatalf("error populating account fixture %+v: %s", acct, err)
				}
			}
			clientsStorer, err := clientsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for clients: %s", err)
			}
			for _, client := range testCase.existingClients {
				err = clientsStorer.Create(context.Background(), client)
				if err != nil {
					t.Fatalf("error populating client fixture %+v: %s", client, err)
				}
			}
			grantsStorer, err := grantsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for grants: %s", err)
			}
			scopesStorer, err := scopesMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for scopes: %s", err)
			}
			for _, scope := range testCase.existingScopes {
				err = scopesStorer.Create(context.Background(), scope)
				if err != nil {
					t.Fatalf("error populating scope fixture %+v: %s", scope, err)
				}
			}
			tokensStorer, err := tokensMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for tokens: %s", err)
			}
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("error creating private key: %s", err)
			}
			publicKey, ok := privateKey.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatalf("expected public key to be an *rsa.PublicKey, got a %T", privateKey.Public())
			}
			emailer := new(MemoryEmailer)
			service := Service{
				TokenExpiresIn: 600,
				Accounts: accounts.Dependencies{
					Storer: acctsStorer,
				},
				Clients: clientsStorer,
				Grants: grants.Dependencies{
					Storer: grantsStorer,
				},
				Refresh: tokens.Dependencies{
					Storer:        tokensStorer,
					JWTPrivateKey: privateKey,
					JWTPublicKey:  publicKey,
					ServiceID:     "test",
				},
				Scopes: scopes.Dependencies{
					Storer: scopesStorer,
				},
				Sessions: sessions.Dependencies{
					JWTPrivateKey: privateKey,
					JWTPublicKey:  publicKey,
					ServiceID:     "test",
				},
				Log:     logger,
				Emailer: emailer,
			}
			service.handleGrantRequest(respRec, req)
			resp := respRec.Result()
			defer resp.Body.Close() //nolint:errcheck // it probably doesn't matter
			gotBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Error reading response body: %v", err)
			}
			if resp.StatusCode != testCase.expectedStatus {
				t.Errorf("Expected response status code to be %d, got %d", testCase.expectedStatus, resp.StatusCode)
			}
			switch strings.ToLower(resp.Header.Get("Content-Type")) {
			case "application/json":
				opts := jsondiff.DefaultConsoleOptions()
				match, diff := jsondiff.Compare([]byte(testCase.expectedBody), gotBody, &opts)
				if match != jsondiff.FullMatch {
					t.Errorf("Unexpected response body: %s", diff)
				}
				if match > jsondiff.NoMatch {
					t.Logf("first argument: %s", testCase.expectedBody)
					t.Logf("second argument: %s", gotBody)
				}
			default:
				if string(gotBody) != testCase.expectedBody {
					t.Errorf("Expected response body to be %q, got %q", testCase.expectedBody, string(gotBody))
				}
			}
			if emailer.LastEmail != testCase.expectedEmail {
				t.Errorf("Expected email to be sent to %q, was sent to %q", testCase.expectedEmail, emailer.LastEmail)
			}
			if !testCase.expectedCode {
				return
			}
			if !codeRE.MatchString(emailer.LastCode) {
				t.Fatalf("Expected an email code, but %q doesn't match our expected code format", emailer.LastCode)
			}

			grant, err := service.Grants.Storer.GetGrantBySource(context.Background(), "email", emailer.LastCode)
			if err != nil {
				t.Fatalf("Error getting grant %q from storer: %s", emailer.LastCode, err)
			}

			if age := time.Since(grant.CreatedAt); age > time.Second {
				t.Errorf("Expected grant to be created within the last second, says it was created %s ago", age)
			}

			if age := time.Until(grant.CreatedAt); age > 0 {
				t.Errorf("Grant somehow created %s from now", age)
			}

			if !grant.UsedAt.IsZero() {
				t.Errorf("Grant expected to be unused, says it was used at %s", grant.UsedAt)
			}

			if len(grant.Scopes) != len(testCase.expectedScopes) {
				t.Errorf("Expected grant to have %d scopes, has %d", len(testCase.expectedScopes), len(grant.Scopes))
			}

			for _, expected := range testCase.expectedScopes {
				var found bool
				for _, got := range grant.Scopes {
					if expected == got {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected grant to have scope %q, is missing", expected)
				}
			}

			for _, got := range grant.Scopes {
				var found bool
				for _, expected := range testCase.expectedScopes {
					if expected == got {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected scope %q found in grant", got)
				}
			}

			if grant.AccountID != testCase.expectedAccountID {
				t.Errorf("Expected grant to have account ID %q, has %q", testCase.expectedAccountID, grant.AccountID)
			}

			if grant.ProfileID != testCase.expectedProfileID {
				t.Errorf("Expected grant to have profile ID %q, has %q", testCase.expectedProfileID, grant.ProfileID)
			}

			if grant.ClientID != testCase.expectedClientID {
				t.Errorf("Expected grant to have client ID %q, has %q", testCase.expectedClientID, grant.ClientID)
			}

			if grant.Used {
				t.Errorf("Expected grant to be unused, says it's used.")
			}
		})
	}
}

func TestCreateToken(t *testing.T) {
	t.Parallel()

	change, err := clients.ChangeSecret([]byte("testing"))
	if err != nil {
		t.Fatalf("error generating secret hash: %v", err)
	}

	secretHash := *change.SecretHash
	secretScheme := *change.SecretScheme

	type testCase struct {
		// existingAccounts are the account fixtures that should be
		// populated before the request
		existingAccounts []accounts.Account

		// existingClients are the client fixtures that should be
		// populated before the request
		existingClients []clients.Client

		// existingScopes are the scope fixtures that should be
		// populated before the request
		existingScopes []scopes.Scope

		// existingTokens are the token fixtures that should be
		// populated before the request
		existingTokens []tokens.RefreshToken

		// existingGrants are the grant fixtures that should be
		// populated before the request
		existingGrants []grants.Grant

		// params are the URL parameters that should be included in the
		// request
		params url.Values

		// overridePath overrides the path portion of the URL,
		// including the query parameters. `params` will have no effect
		// if this is set.
		overridePath string

		// overrideMethod overrides the method of the request
		overrideMethod string

		// body is the body of the request
		body string

		// headers are the request headers to include
		headers http.Header

		// expectedStatus is the HTTP status code we expect for the
		// response
		expectedStatus int

		// expectedBody is the response body we expect for this request
		expectedBody string
	}

	tests := map[string]testCase{
		// test a request that doesn't specify a Content-Type header,
		// which we should explicitly reject because requests without
		// Content-Type headers means the net/http library won't parse
		// the body and that leads to all sorts of weirdness, so we
		// should just explicitly reject them
		"no-content-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: "grant_type=email&code=testcode",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
			},
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedBody:   `{"error": "unsupported_content_type"}`,
		},

		// test a request that specifies an unsupported Content-Type
		// header which we should explicitly reject because requests
		// with Content-Type headers set to anything but
		// application/x-www-form-urlencoded means the net/http library
		// won't parse the body and that leads to all sorts of
		// weirdness, so we should just explicitly reject them
		"unsupported-content-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
			},
			body: `{"grant_type": "email", "code": "testcode"}`,
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/json"},
			},
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedBody:   `{"error": "unsupported_content_type"}`,
		},

		// test a request that doesn't have any client credentials
		// specified
		"no-client-credentials": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "code",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type=email&code=testcode",
			headers: map[string][]string{
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error": "invalid_client"}`,
		},

		// test a client ID that doesn't correspond to an actual client
		"nonexistent-client": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type=email&code=testcode",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("fakeclient:testing123")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 401,
			expectedBody:   `{"error": "invalid_client"}`,
		},

		// test using the wrong client secret
		"wrong-client-secret": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type=email&code=testcode",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing1234")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 401,
			expectedBody:   `{"error": "invalid_client"}`,
		},

		// test omitting the grant_type
		"missing-grant-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "code=testcode",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "unsupported_grant_type"}`,
		},

		// test an unsupported grant_type
		"invalid-grant-type": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type=email2&code=testcode",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "unsupported_grant_type"}`,
		},

		// test an unparseable body
		"unparseable-body": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type;",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "invalid_request"}`,
		},

		// test passing a redirectURI when the client doesn't have any
		"redirect-uri-passed-for-client-without-any": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					Confidential: false,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type=email&code=testcode",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			params: url.Values{
				"client_id":    []string{"testclient"},
				"redirect_uri": []string{"https://www.example.com"},
			},
			// TODO: should this be an invalid client error?
			expectedStatus: 500,
			expectedBody:   `{"error": "server_error"}`,
		},

		// TODO: test granter validation error with granter that redirects

		// test an invalid grant
		"invalid-grant-render": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type=email&code=testcode2",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "invalid_request"}`,
		},

		// TODO: test error checking scopes with granter that redirects

		// TODO: test error checking scopes with granter that renders

		// TODO: test error creating grant inline with granter that redirects

		// TODO: test error creating grant inline with granter that renders

		// TODO: test error exchanging grant with granter that redirects

		// TODO: test error exchanging grant with granter that renders

		// TODO: test exchanging already-used grant with granter that redirects

		// test exchanging already-used grant with granter that renders
		"grant-already-used-render": {
			existingAccounts: []accounts.Account{
				{
					ID:             "test@lockbox.dev",
					ProfileID:      "testing123",
					Created:        time.Now(),
					LastUsed:       time.Now().Add(time.Hour * -24),
					LastSeen:       time.Now().Add(time.Minute * -1),
					IsRegistration: true,
				},
			},
			existingClients: []clients.Client{
				{
					ID:           "testclient",
					Name:         "Testing Client",
					SecretHash:   secretHash,
					SecretScheme: secretScheme,
					Confidential: true,
					CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
					CreatedBy:    "testing",
					CreatedByIP:  "127.0.0.1",
				},
			},
			existingGrants: []grants.Grant{
				{
					ID:         uuidOrFail(t),
					SourceType: "email",
					SourceID:   "testcode",
					CreatedAt:  time.Now().Add(time.Minute * -1),
					AccountID:  "test@lockbox.dev",
					ProfileID:  "testing123",
					ClientID:   "testclient",
					CreateIP:   "127.0.0.1",
					Used:       true,
					UseIP:      "127.0.0.1",
					UsedAt:     time.Now().Add(time.Second * -30),
				},
			},
			existingScopes: []scopes.Scope{
				{
					ID:           "https://scopes.lockbox.dev/testing/default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/default2",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
					IsDefault:    true,
				},
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "grant_type=email&code=testcode",
			headers: map[string][]string{
				"Authorization": {
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": {"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "invalid_grant"}`,
		},

		// TODO: test exchanging non-existent grant with granter that redirects

		// TODO: test error issuing tokens with granter that redirects

		// TODO: test error issuing tokens with granter that renders

		// TODO: test error marking grant as used with granter that redirects

		// TODO: test error marking grant as used with granter that renders

		// TODO: test returning tokens with granter that redirects

		// test returning tokens with granter that renders
		/*
			"happy-case-render": {
				existingAccounts: []accounts.Account{
					{
						ID:             "test@lockbox.dev",
						ProfileID:      "testing123",
						Created:        time.Now(),
						LastUsed:       time.Now().Add(time.Hour * -24),
						LastSeen:       time.Now().Add(time.Minute * -1),
						IsRegistration: true,
					},
				},
				existingClients: []clients.Client{
					{
						ID:           "testclient",
						Name:         "Testing Client",
						SecretHash:   secretHash,
						SecretScheme: secretScheme,
						Confidential: true,
						CreatedAt:    time.Now().Add(time.Hour * -24 * 7),
						CreatedBy:    "testing",
						CreatedByIP:  "127.0.0.1",
					},
				},
				existingGrants: []grants.Grant{
					{
						ID:         uuidOrFail(t),
						SourceType: "email",
						SourceID:   "testcode",
						CreatedAt:  time.Now().Add(time.Minute * -1),
						AccountID:  "test@lockbox.dev",
						ProfileID:  "testing123",
						ClientID:   "testclient",
						CreateIP:   "127.0.0.1",
					},
				},
				existingScopes: []scopes.Scope{
					{
						ID:           "https://scopes.lockbox.dev/testing/default",
						UserPolicy:   scopes.PolicyAllowAll,
						ClientPolicy: scopes.PolicyAllowAll,
						IsDefault:    true,
					},
					{
						ID:           "https://scopes.lockbox.dev/testing/default2",
						UserPolicy:   scopes.PolicyAllowAll,
						ClientPolicy: scopes.PolicyAllowAll,
						IsDefault:    true,
					},
					{
						ID:           "https://scopes.lockbox.dev/testing/not-default",
						UserPolicy:   scopes.PolicyAllowAll,
						ClientPolicy: scopes.PolicyAllowAll,
					},
				},
				body: "grant_type=email&code=testcode",
				headers: map[string][]string{
					"Authorization": {
						"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
					},
					"Content-Type": {"application/x-www-form-urlencoded"},
				},
				expectedStatus: 200,
				expectedBody:   `{"error": "invalid_request"}`,
			},
		*/
	}

	for name, testCase := range tests {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// set up the service
			logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
			if logLevel == "" {
				logLevel = "ERROR"
			}
			logger := yall.New(testLogger.New(t, yall.Severity(logLevel)))
			acctsStorer, err := accountsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for accounts: %s", err)
			}
			for _, acct := range testCase.existingAccounts {
				err = acctsStorer.Create(context.Background(), acct)
				if err != nil {
					t.Fatalf("error populating account fixture %+v: %s", acct, err)
				}
			}
			clientsStorer, err := clientsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for clients: %s", err)
			}
			for _, client := range testCase.existingClients {
				err = clientsStorer.Create(context.Background(), client)
				if err != nil {
					t.Fatalf("error populating client fixture %+v: %s", client, err)
				}
			}
			grantsStorer, err := grantsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for grants: %s", err)
			}
			for _, grant := range testCase.existingGrants {
				err = grantsStorer.CreateGrant(context.Background(), grant)
				if err != nil {
					t.Fatalf("error populating grant fixture %+v: %s", grant, err)
				}
			}
			scopesStorer, err := scopesMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for scopes: %s", err)
			}
			for _, scope := range testCase.existingScopes {
				err = scopesStorer.Create(context.Background(), scope)
				if err != nil {
					t.Fatalf("error populating scope fixture %+v: %s", scope, err)
				}
			}
			tokensStorer, err := tokensMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for tokens: %s", err)
			}
			for _, token := range testCase.existingTokens {
				err = tokensStorer.CreateToken(context.Background(), token)
				if err != nil {
					t.Fatalf("error populating token fixture %+v: %s", token, err)
				}
			}
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("error creating private key: %s", err)
			}
			publicKey, ok := privateKey.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatalf("unexpected public key type, expected *rsa.PublicKey, got %T", privateKey.Public())
			}
			emailer := new(MemoryEmailer)
			service := Service{
				TokenExpiresIn: 600,
				Accounts: accounts.Dependencies{
					Storer: acctsStorer,
				},
				Clients: clientsStorer,
				Grants: grants.Dependencies{
					Storer: grantsStorer,
				},
				Refresh: tokens.Dependencies{
					Storer:        tokensStorer,
					JWTPrivateKey: privateKey,
					JWTPublicKey:  publicKey,
					ServiceID:     "test",
				},
				Scopes: scopes.Dependencies{
					Storer: scopesStorer,
				},
				Sessions: sessions.Dependencies{
					JWTPrivateKey: privateKey,
					JWTPublicKey:  publicKey,
					ServiceID:     "test",
				},
				Log:     logger,
				Emailer: emailer,
			}

			// create request
			params := url.Values{}
			if testCase.params != nil {
				for k, v := range testCase.params {
					params[k] = append(params[k], v...)
				}
			}
			requestPath := "/token?" + params.Encode()
			if testCase.overridePath != "" {
				requestPath = testCase.overridePath
			}
			method := http.MethodPost
			if testCase.overrideMethod != "" {
				method = testCase.overrideMethod
			}
			req := httptest.NewRequest(method, requestPath, bytes.NewBuffer([]byte(testCase.body)))
			req.Header = testCase.headers
			req = req.WithContext(yall.InContext(req.Context(), logger))
			w := httptest.NewRecorder()

			// do the request
			service.handleAccessTokenRequest(w, req)
			resp := w.Result()
			defer resp.Body.Close() //nolint:errcheck // it's probably fine
			gotBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Error reading response body: %v", err)
			}

			// check that the HTTP level stuff is what we expected
			if resp.StatusCode != testCase.expectedStatus {
				t.Errorf("Expected response status code to be %d, got %d", testCase.expectedStatus, resp.StatusCode)
			}
			switch strings.ToLower(resp.Header.Get("Content-Type")) {
			case "application/json":
				opts := jsondiff.DefaultConsoleOptions()
				// TODO: handle comparing tokens, which we don't know the value of ahead of time
				match, diff := jsondiff.Compare([]byte(testCase.expectedBody), gotBody, &opts)
				if match != jsondiff.FullMatch {
					t.Errorf("Unexpected response body: %s", diff)
				}
				if match > jsondiff.NoMatch {
					t.Logf("first argument: %s", testCase.expectedBody)
					t.Logf("second argument: %s", gotBody)
				}
			default:
				if string(gotBody) != testCase.expectedBody {
					t.Errorf("Expected response body to be %q, got %q", testCase.expectedBody, string(gotBody))
				}
			}

			// TODO: check that the application-level parts are what we expected?
			// check that the grant that was exchanged for the token is now marked as used
		})
	}
}
