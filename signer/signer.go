package signer

import (
	"github.com/golang-jwt/jwt/v4"
)

type Signer interface {
	// Sign should return the signed token string with the given claims.
	// The jwt.Token is returned, but consumers should not modify it unless
	// they know exactly what they are doing.
	Sign(claims jwt.MapClaims) (signed string, token *jwt.Token, error error)
}

type Func func(claims jwt.MapClaims) (signed string, token *jwt.Token, error error)

func (f Func) Sign(claims jwt.MapClaims) (signed string, token *jwt.Token, error error) {
	return f(claims)
}
