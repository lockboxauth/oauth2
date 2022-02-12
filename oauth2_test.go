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

	"github.com/nsf/jsondiff"
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
	yall "yall.in"
	testLogger "yall.in/testing"
)

func secretHash(t *testing.T, secret string) string {
	change, err := clients.ChangeSecret([]byte(secret))
	if err != nil {
		t.Fatalf("error generating hash from %q: %v", secret, err)
	}
	return *change.SecretHash
}

func secretScheme(t *testing.T, secret string) string {
	change, err := clients.ChangeSecret([]byte(secret))
	if err != nil {
		t.Fatalf("error generating hash from %q: %v", secret, err)
	}
	return *change.SecretScheme
}

func TestCreateGrantFromEmail(t *testing.T) {
	t.Parallel()

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
					SecretHash:   secretHash(t, "testing"),
					SecretScheme: secretScheme(t, "testing"),
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
				"Authorization": []string{
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			},
			expectedStatus: 204,
			expectedEmail:  "test@lockbox.dev",
			expectedCode:   true,
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
					SecretHash:   secretHash(t, "testing"),
					SecretScheme: secretScheme(t, "testing"),
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
				"Authorization": []string{
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
					SecretHash:   secretHash(t, "testing"),
					SecretScheme: secretScheme(t, "testing"),
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
				"Authorization": []string{
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": []string{"application/json"},
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
					SecretHash:   secretHash(t, "testing"),
					SecretScheme: secretScheme(t, "testing"),
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
				"Authorization": []string{
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": []string{"application/x-www-form-urlencoded"},
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
					SecretHash:   secretHash(t, "testing"),
					SecretScheme: secretScheme(t, "testing"),
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
				"Authorization": []string{
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing")),
				},
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			},
			expectedStatus: 400,
			expectedBody:   `{"error": "invalid_request"}`,
		},

		/*
			// test no client credentials
			"no-client-credentials": {},
			// test getting the client credentials from basic auth
			"basic-auth-client-credentials": {},
			// test getting the client credentials from the request body
			"request-body-client-credentials": {},
			// test setting the client ID, secret, and redirect URI, which
			// is an invalid combination
			"client-id-secret-and-redirect": {},
			// test a client ID that doesn't correspond to an actual client
			"nonexistent-client": {},
			// test using the wrong client secret
			"wrong-client-secret": {},
			// test setting non-default scopes
			"non-default-scopes": {},
			// test that scopes the client isn't authorized to use are
			// stripped
			"strip-unauthorized-client-scopes": {},
			// test that scopes the user isn't authorized to use are
			// stripped
			"strip-unauthorized-user-scopes": {},
		*/
	}

	codeRE, err := regexp.Compile("^(?:[A-Za-z0-9-_]{4})*(?:[A-Za-z0-9-_]{2}|[A-Za-z0-9-_]{3})?$")
	if err != nil {
		t.Fatalf("Error compiling regular expression for emailed codes: %s", err)
	}

	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			logLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
			if logLevel == "" {
				logLevel = "ERROR"
			}
			logger := yall.New(testLogger.New(t, yall.Severity(logLevel)))

			params := url.Values{}
			if tc.params != nil {
				for k, v := range tc.params {
					params[k] = append(params[k], v...)
				}
			}
			requestPath := "/authorize?" + params.Encode()
			if tc.overridePath != "" {
				requestPath = tc.overridePath
			}
			method := http.MethodPost
			if tc.overrideMethod != "" {
				method = tc.overrideMethod
			}
			req := httptest.NewRequest(method, requestPath, bytes.NewBuffer([]byte(tc.body)))
			req.Header = tc.headers
			req = req.WithContext(yall.InContext(req.Context(), logger))
			w := httptest.NewRecorder()
			acctsStorer, err := accountsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for accounts: %s", err)
			}
			for _, acct := range tc.existingAccounts {
				err = acctsStorer.Create(context.Background(), acct)
				if err != nil {
					t.Fatalf("error populating account fixture %+v: %s", acct, err)
				}
			}
			clientsStorer, err := clientsMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for clients: %s", err)
			}
			for _, client := range tc.existingClients {
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
			for _, scope := range tc.existingScopes {
				err = scopesStorer.Create(context.Background(), scope)
				if err != nil {
					t.Fatalf("error populating scope fixture %+v: %s", scope, err)
				}
			}
			tokensStorer, err := tokensMemory.NewStorer()
			if err != nil {
				t.Fatalf("error creating in-memory storer for tokens: %s", err)
			}
			privateKey, err := rsa.GenerateKey(rand.Reader, 128)
			if err != nil {
				t.Fatalf("error creating private key: %s", err)
			}
			emailer := new(MemoryEmailer)
			s := Service{
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
					JWTPublicKey:  privateKey.Public().(*rsa.PublicKey),
					ServiceID:     "test",
				},
				Scopes: scopes.Dependencies{
					Storer: scopesStorer,
				},
				Sessions: sessions.Dependencies{
					JWTPrivateKey: privateKey,
					JWTPublicKey:  privateKey.Public().(*rsa.PublicKey),
					ServiceID:     "test",
				},
				Log:     logger,
				Emailer: emailer,
			}
			s.handleGrantRequest(w, req)
			resp := w.Result()
			defer resp.Body.Close()
			gotBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Error reading response body: %v", err)
			}
			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("Expected response status code to be %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
			switch strings.ToLower(resp.Header.Get("Content-Type")) {
			case "application/json":
				opts := jsondiff.DefaultConsoleOptions()
				match, diff := jsondiff.Compare([]byte(tc.expectedBody), gotBody, &opts)
				if match != jsondiff.FullMatch {
					t.Errorf("Unexpected response body: %s", diff)
				}
				if match > jsondiff.NoMatch {
					t.Logf("first argument: %s", tc.expectedBody)
					t.Logf("second argument: %s", gotBody)
				}
			default:
				if string(gotBody) != tc.expectedBody {
					t.Errorf("Expected response body to be %q, got %q", tc.expectedBody, string(gotBody))
				}
			}
			if emailer.LastEmail != tc.expectedEmail {
				t.Errorf("Expected email to be sent to %q, was sent to %q", tc.expectedEmail, emailer.LastEmail)
			}
			if tc.expectedCode && !codeRE.MatchString(emailer.LastCode) {
				t.Errorf("Expected an email code, but %q doesn't match our expected code format", emailer.LastCode)
			}
		})
	}
}

func TestCreateTokenFromRefreshToken(t *testing.T) {
	t.Parallel()

	// TODO: stand up a server and test exchanging a refresh token for a new token
}

func TestCreateTokenFromEmail(t *testing.T) {
	t.Parallel()

	// TODO: stand up a server and test exchanging an emailed code for a token
}

func TestCreateTokenFromGoogleID(t *testing.T) {
	t.Parallel()

	// TODO: stand up a server and test exchanging a Google ID token for a token
}
