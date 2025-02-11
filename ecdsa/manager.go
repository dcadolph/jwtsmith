package ecdsa

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/dcadolph/jwtsmith/manager"
	"github.com/dcadolph/jwtsmith/refresher"
	"github.com/dcadolph/jwtsmith/validation"
	"github.com/golang-jwt/jwt/v4"
)

type managerECDSA struct {
	validation.TokenValidator
	refresher.Refresher
	signingMethod jwt.SigningMethod
	pubKey        *ecdsa.PublicKey
	privateKey    *ecdsa.PrivateKey
	// TODO: Identify additional ECDSAManagerOpts fields that would make sense, such as "static claims" perhaps, which could be claims added to every token or something.
}

// NewDefaultManager() // Make this one create the public and private files, returns public and private keys, and

// NewManager returns a new ECDSA JWT manager.Manager.
func NewManager(signingMethod jwt.SigningMethod, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, opts ...ManagerOpt) (manager.Manager, error) {

	if signingMethod == nil {
		return nil, fmt.Errorf("%w: method cannot be nil", ErrInvalidValue)
	}

	methodAlg := signingMethod.Alg()
	if methodAlg == "" {
		return nil, fmt.Errorf("%w: method algorithm cannot be empty string", ErrInvalidValue)
	}

	ecdsaMethod, ok := signingMethod.(*jwt.SigningMethodECDSA)
	if !ok {
		return nil, fmt.Errorf(
			"%w: invalid signing method: expected ECDSA (ES256, ES384, ES512) but got %T",
			ErrInvalidType, signingMethod,
		)
	}

	mgr := &managerECDSA{
		pubKey:        publicKey,
		privateKey:    privateKey,
		signingMethod: ecdsaMethod,
	}

	var mgrOpts = &managerOpt{}
	for _, opt := range opts {
		opt(mgrOpts)
	}

	validator, err := Validator(signingMethod, publicKey, mgrOpts.tokenCheckFunc...)
	if err != nil {
		return nil, fmt.Errorf("NewManagerECSDA: %w", err) // IMPROVE ME
	}
	mgr.TokenValidator = validator

	signer, signerErr :=

	return mgr, nil
}
