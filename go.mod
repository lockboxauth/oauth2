module impractical.co/auth/oauth2

// TODO: use the real version of these
replace (
	impractical.co/auth/accounts v0.0.0 => ../accounts
	impractical.co/auth/clients v0.0.0 => ../clients
	impractical.co/auth/grants v0.0.0 => ../grants
	impractical.co/auth/hmac v0.0.0 => ../hmac
	impractical.co/auth/scopes v0.0.0 => ../scopes
	impractical.co/auth/tokens v0.0.0 => ../tokens
	impractical.co/googleid v0.0.0 => ../../impractical.co/googleid
)

require (
	darlinggo.co/trout v1.0.1
	github.com/coreos/go-oidc v2.0.0+incompatible
	github.com/hashicorp/go-uuid v1.0.0
	impractical.co/auth/accounts v0.0.0
	impractical.co/auth/clients v0.0.0
	impractical.co/auth/grants v0.0.0
	impractical.co/auth/scopes v0.0.0
	impractical.co/auth/sessions v0.0.0-20180908101947-9cd90b17e6bd
	impractical.co/auth/tokens v0.0.0
	impractical.co/googleid v0.0.0
	yall.in v0.0.1
)
