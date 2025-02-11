package ecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	jwt2 "github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/validation"
	"github.com/golang-jwt/jwt/v4"
)

//DIR BY ALG A GOOD IDEA

// TODO: look at JSON.Number use in other places. This is a parser option, and you may want to by default have it off but let folks set it.
// TODO: you did it in time.go in claims/
type ecdsaValidator struct {
	method          jwt.SigningMethod
	publicKeyFunc   jwt.Keyfunc
	publicKey       *ecdsa.PublicKey
	staticCheckFunc []validation.TokenCheckFunc
	parser          *jwt.Parser
}

func Validator(method jwt.SigningMethod, key *ecdsa.PublicKey, staticCheckFunc ...validation.TokenCheckFunc) (validation.TokenValidator, error) {

	if method == nil {
		return nil, fmt.Errorf("%w: method cannot be nil", ErrInvalidValue)
	}

	methodAlg := method.Alg()
	if methodAlg == "" {
		return nil, fmt.Errorf("%w: method algorithm cannot be empty string", ErrInvalidValue)
	}

	ecdsaMethod, ok := method.(*jwt.SigningMethodECDSA)
	if !ok {
		return nil, fmt.Errorf(
			"%w: invalid signing method: expected ECDSA (ES256, ES384, ES512) but got %T",
			ErrInvalidType, method,
		)
	}

	if key == nil {
		return nil, fmt.Errorf("%w: public key cannot be nil", ErrInvalidValue)
	}

	keyFunc, kfErr := jwt2.PublicKeyFunc(ecdsaMethod, key)
	if kfErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrGet, kfErr)
	}

	return &ecdsaValidator{
		method:          ecdsaMethod,
		publicKeyFunc:   keyFunc,
		publicKey:       key,
		staticCheckFunc: staticCheckFunc,
		parser:          jwt.NewParser(jwt.WithValidMethods([]string{methodAlg})),
	}, nil

}

func (v *ecdsaValidator) Validate(token string, checkFunc ...validation.TokenCheckFunc) error {

	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("%w: token cannot be empty", ErrInvalidValue)
	}

	parsedClaims := jwt.MapClaims{}
	parsedToken, parseErr := v.parser.ParseWithClaims(token, parsedClaims, v.publicKeyFunc)
	if parseErr != nil {
		return fmt.Errorf("%w: %w", ErrParse, parseErr)
	}

	for _, check := range v.staticCheckFunc {
		if err := check(parsedToken); err != nil {
			return fmt.Errorf("%w: static check function error: %w", ErrCheck, err)
		}
	}

	for _, check := range checkFunc {
		if err := check(parsedToken); err != nil {
			return fmt.Errorf("%w: check function error: %w", ErrCheck, err)
		}
	}

	return nil
}

// DisableRegisteredClaimsValidation disables standard/registered claims validation for
// the TokenValidator. This means that claims like "exp" and "iat" will not be validated.
// Only disable registered claims validation if:
// A) You are validating things like "exp" and "iat" using your own TokenCheckFunc.
// B) You have a compelling reason to NOT validate registered JWT claims.
func (v *ecdsaValidator) DisableRegisteredClaimsValidation() {
	v.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{v.method.Alg()}),
		jwt.WithoutClaimsValidation(),
	)
}

// EnableRegisteredClaimsValidation enables standard/registered claims validation for
// the TokenValidator. Registered claims validation is enabled by default, so this only
// needs to be called if DisableRegisteredClaimsValidation was used to disable it.
func (v *ecdsaValidator) EnableRegisteredClaimsValidation() {
	v.parser = jwt.NewParser(jwt.WithValidMethods([]string{v.method.Alg()}))
}
