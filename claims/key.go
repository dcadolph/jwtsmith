package claims

const (

	// Standard JWT claims: RFC75|9.

	KeyAudience  = "aud" // KeyAudience is the audience claim key.
	KeyExpires   = "exp" // KeyExpires is the expiration time claim key.
	KeyIssuedAt  = "iat" // KeyIssuedAt is the issued at claim key.
	KeyIssuer    = "iss" // KeyIssuer is the issuer claim key.
	KeyJTI       = "jti" // KeyJTI is the JWT ID claim key.
	KeyNotBefore = "nbf" // KeyNotBefore is the not-before claim key.
	KeySubject   = "sub" // KeySubject is the subject claim key.

	// Additional out-of-the-box claims keys.
)
