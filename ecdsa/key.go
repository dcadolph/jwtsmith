package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

// GenerateECDSAKeyPair generates an ECDSA key pair based on the given curve.
// It returns the private and public keys.
func GenerateECDSAKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// ValidateKeyPair validates the given public and private key pair. It's useful
// for ensuring that a given public and private key are indeed pairs.
func ValidateKeyPair(public *ecdsa.PublicKey, private *ecdsa.PrivateKey) error {

	const predefinedMessage = "ECDSA key validation"
	hash := sha256.Sum256([]byte(predefinedMessage))

	r, s, err := ecdsa.Sign(rand.Reader, private, hash[:])
	if err != nil {
		return fmt.Errorf("%w: failed to sign message: %w", ErrSign, err)
	}

	if !ecdsa.Verify(public, hash[:], r, s) {
		return fmt.Errorf("%w: invalid key pair: public and private keys do not match", ErrInvalidKeyPair)
	}

	return nil
}

// ValidateECDSAMethodAndKey ensures the signing method and signing key are compatible.
func ValidateECDSAMethodAndKey(method jwt.SigningMethod, signingKey *ecdsa.PrivateKey) error {

	if method == nil {
		return fmt.Errorf("%w: method cannot be nil", ErrInvalidValue)
	}

	methodAlg := method.Alg()
	if methodAlg == "" {
		return fmt.Errorf("%w: method algorithm cannot be empty string", ErrInvalidValue)
	}

	ecdsaMethod, ok := method.(*jwt.SigningMethodECDSA)
	if !ok {
		return fmt.Errorf(
			"%w: invalid signing method: expected ECDSA (ES256, ES384, ES512) but got %T",
			ErrInvalidType, method,
		)
	}

	if signingKey == nil {
		return fmt.Errorf("%w: public key cannot be nil", ErrInvalidValue)
	}

	// Ensure the signing method is an ECDSA method
	ecdsaMethod, isECDSA := method.(*jwt.SigningMethodECDSA)
	if !isECDSA {
		return fmt.Errorf("%w: expected ECDSA (ES256, ES384, ES512) but got %T", ErrInvalidMethod, method)
	}

	// Determine the curve size from the method and match it with the key
	switch ecdsaMethod.CurveBits {
	case 256:
		if signingKey.Curve.Params().BitSize != 256 {
			return fmt.Errorf(
				"%w: signing key curve size mismatch: expected 256-bit key for %s but got %d-bit",
				ErrInvalidSize, ecdsaMethod.Alg(), signingKey.Curve.Params().BitSize,
			)
		}
	case 384:
		if signingKey.Curve.Params().BitSize != 384 {
			return fmt.Errorf(
				"%w: signing key curve size mismatch: expected 384-bit key for %s but got %d-bit",
				ErrInvalidSize, ecdsaMethod.Alg(), signingKey.Curve.Params().BitSize,
			)
		}
	case 521:
		if signingKey.Curve.Params().BitSize != 521 {
			return fmt.Errorf(
				"%w: signing key curve size mismatch: expected 521-bit key for %s but got %d-bit",
				ErrInvalidSize, ecdsaMethod.Alg(), signingKey.Curve.Params().BitSize,
			)
		}
	default:
		return fmt.Errorf(
			"%w: unsupported ECDSA curve size: %d bits",
			ErrInvalidSize, ecdsaMethod.CurveBits,
		)
	}

	return nil
}

// SavePrivateKey saves the private key to a PEM file.
func SavePrivateKey(fileName string, privateKey *ecdsa.PrivateKey) error {

	data, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	})

	err = os.WriteFile(fileName, pemEncoded, 0600)
	if err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}
	return nil
}

// SavePublicKey saves the public key to a PEM file.
func SavePublicKey(fileName string, publicKey *ecdsa.PublicKey) error {

	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	})

	err = os.WriteFile(fileName, pemEncoded, 0644)
	if err != nil {
		return fmt.Errorf("failed to write public key to file: %w", err)
	}
	return nil
}
