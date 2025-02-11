package jwt

import (
	"time"
)

const (
	// DefaultExpiration is the default expiration time for a token.
	DefaultExpiration = 24 * time.Hour
	// DefaultIssuer is the default issuer for a token.
	DefaultIssuer = "jwtsmith"
)
