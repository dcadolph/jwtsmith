package ecdsa

import (
	"github.com/golang-jwt/jwt/v4"
)

type SignerOpt func(opts *signerOpt)

type signerOpt struct {
	staticHeaders map[string]any
	staticClaims  jwt.MapClaims
}

func SignerOptsTokenStaticHeaders(headers map[string]any) SignerOpt {
	return func(opts *signerOpt) {
		opts.staticHeaders = headers
	}
}

func SignerOptsStaticClaims(claims jwt.MapClaims) SignerOpt {
	return func(opts *signerOpt) {
		opts.staticClaims = claims
	}
}

// TODO: do not allow static claims for iat, exp, nbf...
func filterStaticClaims(claims jwt.MapClaims) jwt.MapClaims {
	return claims
}
