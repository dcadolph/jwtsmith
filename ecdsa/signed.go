package ecdsa

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	DefaultExpiration = time.Hour
	DefaultIssuer     = "jwtsmith"
	HeaderKeyAlg      = "alg"
	HeaderKeyTyp      = "typ"
)

// Signed returns a signed string and jwt.Token from the given claims, signing method, and signing key.
//
// Support across the code is designed for asymmetric signing methods, so HMAC signing methods are not
// supported, even though the signing key is passed in and SignedString would be capable of signing with
// HMAC methods.
//
// No claims are required, though certain claims will be required based on what type of token/token validation
// consumers need. Consumers can provide their own claims, or defer to the defaults set by this
// function. Expires-at (exp), issued-at (iat), and not-before (nbf) are set based on the given jwt.MapClaims.
// If provided and valid, these values are used. If invalid, ErrInvalidClaimValue is returned.
// If the following claims are not provided, the following defaults are used:
// - exp: time.Now + DefaultExpiration
// - iat: time.Now
// - nbf: time.Now
// - jti: random UUID
// - iss: DefaultIssuer
// To dictate expires-at by argument, use SignedWithExpiration.
//
// Headers can be any custom headers. Headers for "alg" and "typ" are ignored, since these are set internally
// when the token is signed.
func Signed(method jwt.SigningMethod, signingKey *ecdsa.PrivateKey, headers map[string]any, mapClaims jwt.MapClaims) (string, *jwt.Token, error) { //nolint:lll // Do not want to multi-line.

	if method == nil {
		return "", nil, fmt.Errorf("%w: signing method cannot be nil", ErrInvalidValue)
	}

	if signingKey == nil {
		return "", nil, fmt.Errorf("%w: signing key cannot be nil", ErrInvalidValue)
	}

	// Copy the claims to avoid modifying the original.
	var claimsCopy jwt.MapClaims
	if len(mapClaims) < 1 {
		claimsCopy = jwt.MapClaims{}
	} else {
		claimsCopy = claims.DeepCopy(mapClaims)
	}

	now := time.Now()

	exp, expErr := claims.ExpiresAt(claimsCopy)
	switch {
	case expErr == nil && exp.Before(now):
		return "", nil, fmt.Errorf("%w: expiration time is in the past", ErrExpired)
	case expErr == nil:
		claims.SetExpiresAt(claimsCopy, exp)
	default:
		claims.SetExpiresAt(claimsCopy, now.Add(DefaultExpiration))
	}

	iat, iatErr := claims.IssuedAt(claimsCopy)
	switch {
	case iatErr == nil && iat.After(now):
		return "", nil, fmt.Errorf("%w: issued at time is in the future", ErrNotReady)
	case iatErr == nil:
		claims.SetIssuedAt(claimsCopy, iat)
	default:
		claims.SetIssuedAt(claimsCopy, now)
	}

	nbf, nbfErr := claims.NotBefore(claimsCopy)
	if nbfErr == nil {
		claims.SetNotBefore(claimsCopy, nbf)
	} else { // Either DNE or invalid timestamp.
		claims.SetNotBefore(claimsCopy, now)
	}

	_, issErr := claims.Issuer(claimsCopy)
	if errors.Is(issErr, claims.ErrNotFound) {
		claims.SetIssuer(claimsCopy, DefaultIssuer)
	} else if issErr != nil {
		return "", nil, fmt.Errorf("%w: getting issuer claim: %w", ErrGet, issErr)
	}

	_, jtiErr := claims.ID(claimsCopy)
	if errors.Is(jtiErr, claims.ErrNotFound) {
		claims.SetID(claimsCopy, uuid.NewString())
	}

	token := jwt.NewWithClaims(method, claimsCopy)

	for k, v := range headers {
		if k == HeaderKeyAlg || k == HeaderKeyTyp {
			continue
		}
		token.Header[k] = v
	}

	ss, ssErr := token.SignedString(signingKey)
	if ssErr != nil {
		return "", nil, fmt.Errorf("%w: building signed string: %w", ErrEncode, ssErr)
	}

	return ss, token, nil
}
