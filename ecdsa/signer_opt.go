package ecdsa

import (
	"github.com/golang-jwt/jwt/v4"
)

type SignerOpts func(opts *signerOpts)

type signerOpts struct {
	headers      map[string]any
	staticClaims map[string]any
}

func SignerOptsTokenHeaders(headers map[string]any) SignerOpts {
	return func(opts *signerOpts) {
		opts.headers = headers
	}
}

func SignerOptsStaticClaims() {

}

// TODO: do not allow static claims for iat, exp, nbf...
func filterStaticClaims(claims jwt.MapClaims) jwt.MapClaims {
	return claims
}
