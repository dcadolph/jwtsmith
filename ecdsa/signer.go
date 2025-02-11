package ecdsa

import (
	"crypto/ecdsa"

	"github.com/dcadolph/jwtsmith/signer"
	"github.com/golang-jwt/jwt/v4"
)

type ecdsaSigner struct {
	signingMethod jwt.SigningMethod
	privateKey    *ecdsa.PrivateKey
	staticClaims  jwt.MapClaims
	staticHeaders map[string]any
}

func Signer(signingMethod jwt.SigningMethod, privateKey *ecdsa.PrivateKey, opts ...SignerOpt) (signer.Signer, error) {

	if err := ValidateECDSAMethodAndKey(signingMethod, privateKey); err != nil {
		return nil, err
	}

	var sOpts = &signerOpt{}
	for _, opt := range opts {
		opt(sOpts)
	}

}

func (s *ecdsaSigner) Sign(claims jwt.MapClaims) (signed string, token *jwt.Token, error error) {

}
