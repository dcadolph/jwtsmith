package validation

import (
	"crypto/ecdsa"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/golang-jwt/jwt/v4"
)

// Break all this out. Basically design phase.

type TokenValidator interface {
	Validate(token string, checkFunc ...TokenCheckFunc) error
}

type TokenValidatorFunc func(token string, checkFunc ...TokenCheckFunc) error

func (f TokenValidatorFunc) Validate(token string, checkFunc ...TokenCheckFunc) error {
	return f(token, checkFunc...)
}

type defaultValidator struct {
	method          jwt.SigningMethod
	publicKey       *ecdsa.PublicKey
	staticCheckFunc []TokenCheckFunc
}

func DefaultValidatorFromPublicKey(method jwt.SigningMethod, publicKey any, staticCheckFunc ...TokenCheckFunc) TokenValidator {

}

//TODO: Instead of claims func, have full on TokenCheckFunc too. Those can leverage claim funcs too, but much more (headers, etc).

// Static claims.CheckFunc will be applied for each call to Validate, regardless of the claims.CheckFunc that may be passed to the Validate call itself.
func DefaultValidator(method jwt.SigningMethod, staticCheckFunc ...claims.CheckFunc) TokenValidator {

}

func (v *defaultValidator) Validate(token string, publicKey string, checkFunc ...claims.CheckFunc) error {

}
