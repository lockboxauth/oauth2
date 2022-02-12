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
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
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
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
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
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
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
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev&client_id=testclient&client_secret=testing",
			headers: map[string][]string{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
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
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": []string{
					"Basic " + base64.StdEncoding.EncodeToString([]byte("fakeclient:testing123")),
				},
				"Content-Type": []string{"application/x-www-form-urlencoded"},
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
				{
					ID:           "https://scopes.lockbox.dev/testing/not-default",
					UserPolicy:   scopes.PolicyAllowAll,
					ClientPolicy: scopes.PolicyAllowAll,
				},
			},
			body: "response_type=email&email=test@lockbox.dev",
			headers: map[string][]string{
				"Authorization": []string{
					"Basic " + base64.StdEncoding.EncodeToString([]byte("testclient:testing1234")),
				},
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			},
			expectedStatus: 401,
			expectedBody:   `{"error": "invalid_client"}`,
		},

		/*
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
			if !tc.expectedCode {
				return
			}
			if !codeRE.MatchString(emailer.LastCode) {
				t.Fatalf("Expected an email code, but %q doesn't match our expected code format", emailer.LastCode)
			}

			grant, err := s.Grants.Storer.GetGrantBySource(context.Background(), "email", emailer.LastCode)
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

			if len(grant.Scopes) != len(tc.expectedScopes) {
				t.Errorf("Expected grant to have %d scopes, has %d", len(tc.expectedScopes), len(grant.Scopes))
			}

			for _, expected := range tc.expectedScopes {
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
				for _, expected := range tc.expectedScopes {
					if expected == got {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected scope %q found in grant", got)
				}
			}

			if grant.AccountID != tc.expectedAccountID {
				t.Errorf("Expected grant to have account ID %q, has %q", tc.expectedAccountID, grant.AccountID)
			}

			if grant.ProfileID != tc.expectedProfileID {
				t.Errorf("Expected grant to have profile ID %q, has %q", tc.expectedProfileID, grant.ProfileID)
			}

			if grant.ClientID != tc.expectedClientID {
				t.Errorf("Expected grant to have client ID %q, has %q", tc.expectedClientID, grant.ClientID)
			}

			if grant.Used {
				t.Errorf("Expected grant to be unused, says it's used.")
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
