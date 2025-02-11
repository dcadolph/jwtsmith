package ecdsa

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/refresher"
	"github.com/golang-jwt/jwt/v4"
)

func Refresher(method jwt.SigningMethod, publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, defaultExpiration time.Duration) (refresher.Refresher, error) {

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

	if publicKey == nil {
		return nil, fmt.Errorf("%w: public key cannot be nil", ErrInvalidValue)
	}

	if privateKey == nil {
		return nil, fmt.Errorf("%w: private key cannot be nil", ErrInvalidValue)
	}

	if err := ValidateKeyPair(publicKey, privateKey); err != nil {
		return nil, err
	}

	f := refresher.Func(func(token any) (*jwt.Token, string, error) {

		var signedString string
		var signedStringErr error

		switch tok := token.(type) {
		case *jwt.Token:
			signedString, signedStringErr = tok.SignedString(privateKey)
			if signedStringErr != nil {
				return nil, "", signedStringErr // TODO wrap me
			}
		case string:
			signedString = tok
		default:
			return nil, "", fmt.Errorf(
				"%w: invalid token type: %T: expected *jwt.Token or signed string",
				ErrInvalidType, token,
			)
		}

		return refreshToken(ecdsaMethod, publicKey, privateKey, defaultExpiration, signedString)
	})

	return f, nil
}

// RefreshToken refreshes the given token, returning the new token string.
//
// Existing token is parsed using the given public key, in order to validate and modify
// a subset of the claims. The refreshed/new token is signed using the given private key.
//
// NotBefore (nbf) and IssuedAt (iat) are updated to the current time, and ExpiresAt (exp)
// is updated using the expiration derived from the original token. If the expiration cannot
// be retrieved from the token's claims, the given default expiration is used. If given
// expiration is less than or equal to zero, DefaultRefreshExpiration is used.
//
// If the given default expiration is less than or equal to zero, DefaultExpiration is used.
func refreshToken(method jwt.SigningMethod, publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey, defaultExpiration time.Duration, token string) (*jwt.Token, string, error) { //nolint:lll // Do not want to multi-line.

	if strings.TrimSpace(token) == "" {
		return nil, "", fmt.Errorf("%w: token cannot be empty string", ErrInvalidValue)
	}

	if validateErr := ValidateKeyPair(publicKey, privateKey); validateErr != nil {
		return nil, "", validateErr
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	keyFunc, keyFuncErr := keys.PublicKeyFunc(method, publicKey)
	if keyFuncErr != nil {
		return nil, "", fmt.Errorf("creating key function: %w", keyFuncErr)
	}

	var parsed jwt.MapClaims
	_, parseErr := parser.ParseWithClaims(token, &parsed, keyFunc)
	if parseErr != nil {
		return nil, "", errors.Join(ErrInvalidToken, parseErr)
	}

	// Issued-at used to (attempt to) derive expiration duration.
	issuedAt, iatErr := claims.IssuedAt(parsed)
	if iatErr != nil {
		return nil, "", fmt.Errorf("invalid issued at (iat) claim: %w", iatErr)
	}

	now := time.Now()

	var newExpireAt time.Time
	expiresAt, expErr := claims.ExpiresAt(parsed)
	switch {
	case errors.Is(expErr, claims.ErrNotFound): // Not in claims, so using fallback(s).
		if defaultExpiration <= 0 {
			newExpireAt = now.Add(DefaultExpiration)
		} else {
			newExpireAt = now.Add(defaultExpiration)
		}
	case expErr != nil: // Something unexpected happened.
		return nil, "", fmt.Errorf("invalid expires at (exp) claim: %w", expErr)
	default: // We can derive the right expiration by subtracting the issued-at date from the existing expires-at.
		newExpireAt = now.Add(expiresAt.Sub(issuedAt))
	}

	claims.SetExpiresAt(parsed, newExpireAt)
	claims.SetNotBefore(parsed, now)
	claims.SetIssuedAt(parsed, now)

	refreshed := jwt.NewWithClaims(method, parsed)

	signedRefreshed, err := refreshed.SignedString(privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("%w: signing refreshed token: %w", ErrSign, err)
	}

	return refreshed, signedRefreshed, nil
}
