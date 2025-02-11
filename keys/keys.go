package keys

import (
	"fmt"

	jwt2 "github.com/dcadolph/jwtsmith/jwt"
	"github.com/golang-jwt/jwt/v4"
)

// PublicKeyFunc returns a jwt.KeyFunc to validate JWT strings.
//
// Function will verify that the token's signing method matches the
// given method, then return the public key.
func PublicKeyFunc(method jwt.SigningMethod, key any) (jwt.Keyfunc, error) {

	if method == nil {
		return nil, fmt.Errorf("%w: method cannot be nil", jwt2.ErrInvalidValue)
	}

	if key == nil {
		return nil, fmt.Errorf("%w: key cannot be nil", jwt2.ErrInvalidValue)
	}

	if method.Alg() == "" {
		return nil, fmt.Errorf("%w: method algorithm cannot be empty string", jwt2.ErrInvalidValue)
	}

	f := func(token *jwt.Token) (any, error) {

		tokenAlg := token.Method.Alg()

		// If token was unsigned, it's invalid.
		if tokenAlg == "" {
			return nil, fmt.Errorf(
				"%w: token method algorithm cannot be empty string: token likely unsigned",
				jwt2.ErrInvalidValue,
			)
		}

		switch token.Method.(type) {

		case *jwt.SigningMethodECDSA, *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
			methodAlg := method.Alg()
			if methodAlg != tokenAlg {
				return nil, fmt.Errorf(
					"%w: want %s got %s",
					jwt2.ErrInvalidSigningMethod, methodAlg, tokenAlg,
				)
			}
			return key, nil

		default:
			return nil, fmt.Errorf(
				"%w: invalid signing method: %v: expected ECDSA, RSA, or RSAPSS",
				jwt2.ErrInvalidSigningMethod, token.Method,
			)
		}
	}

	return f, nil
}

//// PrivateKey returns the ECDSA private key from the given private key file path.
////
//// File content must be PEM-encoded private key, or ErrDecode will be returned.
//func PrivateKey(privateKeyFilePath string) (*ecdsa.PrivateKey, error) {
//
//	signBytes, readErr := os.ReadFile(privateKeyFilePath)
//	if readErr != nil {
//		return nil, fmt.Errorf("%w: reading ECDSA JWT private key pem file %s: %w", ErrRead, privateKeyFilePath, readErr)
//	}
//
//	signKey, err := jwt.ParseECPrivateKeyFromPEM(signBytes)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT private key pem file %s: %w", ErrParse, privateKeyFilePath, err)
//	}
//
//	return signKey, nil
//}
//
//// PrivateKeyFromBytes returns the ECDSA private key from the given private key bytes.
//func PrivateKeyFromBytes(privateKey []byte) (*ecdsa.PrivateKey, error) {
//
//	if len(privateKey) == 0 {
//		return nil, fmt.Errorf("%w: private key bytes cannot be empty", ErrInvalidParam)
//	}
//
//	signKey, err := jwt.ParseECPrivateKeyFromPEM(privateKey)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT private key pem: %w", ErrParse, err)
//	}
//
//	return signKey, nil
//}
//
//// PrivateKeyFromString returns the ECDSA private key from the given private key string.
//func PrivateKeyFromString(key string) (*ecdsa.PrivateKey, error) {
//
//	if strings.TrimSpace(key) == "" {
//		return nil, fmt.Errorf("%w: private key cannot be empty", ErrInvalidParam)
//	}
//
//	signKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(key))
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT private key pem: %w", ErrParse, err)
//	}
//
//	return signKey, nil
//}
//
//// PrivateKeyBase64 is PrivateKey but expects the file content to be base64 encoded PEM.
//func PrivateKeyBase64(privateKeyFilePath string) (*ecdsa.PrivateKey, error) {
//
//	signBytes, readErr := os.ReadFile(privateKeyFilePath)
//	if readErr != nil {
//		return nil, fmt.Errorf(
//			"%w: reading ECDSA JWT private key pem file %s: %w",
//			ErrRead, privateKeyFilePath, readErr,
//		)
//	}
//
//	decoded, decodeErr := base64.StdEncoding.DecodeString(string(signBytes))
//	if decodeErr != nil {
//		return nil, fmt.Errorf(
//			"%w: decoding base64 JWT private key pem file %s: %w",
//			ErrDecode, privateKeyFilePath, decodeErr,
//		)
//	}
//
//	signKey, err := jwt.ParseECPrivateKeyFromPEM(decoded)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT private key pem file %s: %w", ErrParse, privateKeyFilePath, err)
//	}
//
//	return signKey, nil
//}
//
//// PrivateKeyFromBase64Bytes returns the ECDSA private key from the given private key bytes.
//func PrivateKeyFromBase64Bytes(b []byte) (*ecdsa.PrivateKey, error) {
//
//	if len(b) == 0 {
//		return nil, fmt.Errorf("%w: private key bytes cannot be empty", ErrInvalidParam)
//	}
//
//	decoded, decodeErr := base64.StdEncoding.DecodeString(string(b))
//	if decodeErr != nil {
//		return nil, fmt.Errorf("%w: decoding base64 JWT private key pem: %w", ErrDecode, decodeErr)
//	}
//
//	signKey, err := jwt.ParseECPrivateKeyFromPEM(decoded)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT private key pem: %w", ErrParse, err)
//	}
//
//	return signKey, nil
//}
//
//// PrivateKeyFromBase64String returns the ECDSA private key from the given private key string.
//func PrivateKeyFromBase64String(key string) (*ecdsa.PrivateKey, error) {
//
//	if strings.TrimSpace(key) == "" {
//		return nil, fmt.Errorf("%w: private key cannot be empty", ErrInvalidParam)
//	}
//
//	decoded, decodeErr := base64.StdEncoding.DecodeString(key)
//	if decodeErr != nil {
//		return nil, fmt.Errorf("%w: decoding base64 JWT private key pem: %w", ErrDecode, decodeErr)
//	}
//
//	signKey, err := jwt.ParseECPrivateKeyFromPEM(decoded)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT private key pem: %w", ErrParse, err)
//	}
//
//	return signKey, nil
//}
//
//// PublicKey returns the ECDSA public key from the given public key file path.
////
//// File content must be PEM-encoded public key, or ErrDecode will be returned.
//func PublicKey(publicKeyFilePath string) (*ecdsa.PublicKey, error) {
//
//	verifyBytes, err := os.ReadFile(publicKeyFilePath)
//	if err != nil {
//		return nil, fmt.Errorf("%w: reading ECDSA JWT public key pem file %s: %w", ErrRead, publicKeyFilePath, err)
//	}
//
//	verifyKey, err := jwt.ParseECPublicKeyFromPEM(verifyBytes)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT public key pem file %s: %w", ErrParse, publicKeyFilePath, err)
//	}
//
//	return verifyKey, nil
//}
//
//// PublicKeyFromBytes returns the ECDSA public key from the given public key bytes.
//func PublicKeyFromBytes(b []byte) (*ecdsa.PublicKey, error) {
//
//	if len(b) == 0 {
//		return nil, fmt.Errorf("%w: public key bytes cannot be empty", ErrInvalidParam)
//	}
//
//	verifyKey, err := jwt.ParseECPublicKeyFromPEM(b)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT public key pem: %w", ErrParse, err)
//	}
//
//	return verifyKey, nil
//}
//
//// PublicKeyFromString returns the ECDSA public key from the given public key string.
//func PublicKeyFromString(key string) (*ecdsa.PublicKey, error) {
//
//	if strings.TrimSpace(key) == "" {
//		return nil, fmt.Errorf("%w: public key cannot be empty", ErrInvalidParam)
//	}
//
//	verifyKey, err := jwt.ParseECPublicKeyFromPEM([]byte(key))
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT public key pem: %w", ErrParse, err)
//	}
//
//	return verifyKey, nil
//}
//
//// PublicKeyBase64 is PublicKey but expects the file content to be base64 encoded PEM.
//func PublicKeyBase64(publicKeyFilePath string) (*ecdsa.PublicKey, error) {
//
//	verifyBytes, readErr := os.ReadFile(publicKeyFilePath)
//	if readErr != nil {
//		return nil, fmt.Errorf("%w: reading ECDSA JWT public key pem file %s: %w", ErrRead, publicKeyFilePath, readErr)
//	}
//
//	decoded, decodeErr := base64.StdEncoding.DecodeString(string(verifyBytes))
//	if decodeErr != nil {
//		return nil, fmt.Errorf("%w: decoding base64 JWT public key pem file %s: %w", ErrDecode, publicKeyFilePath, decodeErr)
//	}
//
//	verifyKey, err := jwt.ParseECPublicKeyFromPEM(decoded)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT public key pem file %s: %w", ErrParse, publicKeyFilePath, err)
//	}
//
//	return verifyKey, nil
//}
//
//// PublicKeyFromBase64Bytes returns the ECDSA public key from the given public key bytes.
//func PublicKeyFromBase64Bytes(b []byte) (*ecdsa.PublicKey, error) {
//
//	if len(b) == 0 {
//		return nil, fmt.Errorf("%w: public key bytes cannot be empty", ErrInvalidParam)
//	}
//
//	decoded, decodeErr := base64.StdEncoding.DecodeString(string(b))
//	if decodeErr != nil {
//		return nil, fmt.Errorf("%w: decoding base64 JWT public key pem: %w", ErrDecode, decodeErr)
//	}
//
//	verifyKey, err := jwt.ParseECPublicKeyFromPEM(decoded)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT public key pem: %w", ErrParse, err)
//	}
//
//	return verifyKey, nil
//}
//
//// PublicKeyFromBase64String returns the ECDSA public key from the given public key string.
//func PublicKeyFromBase64String(key string) (*ecdsa.PublicKey, error) {
//
//	if strings.TrimSpace(key) == "" {
//		return nil, fmt.Errorf("%w: public key cannot be empty", ErrInvalidParam)
//	}
//
//	decoded, decodeErr := base64.StdEncoding.DecodeString(key)
//	if decodeErr != nil {
//		return nil, fmt.Errorf("%w: decoding base64 JWT public key pem: %w", ErrDecode, decodeErr)
//	}
//
//	verifyKey, err := jwt.ParseECPublicKeyFromPEM(decoded)
//	if err != nil {
//		return nil, fmt.Errorf("%w: parsing ECDSA JWT public key pem: %w", ErrParse, err)
//	}
//
//	return verifyKey, nil
//}
//
//// ValidateKeyPair validates the given public and private key pair. It's useful
//// for ensuring that a given public and private key are indeed pairs.
//func ValidateKeyPair(public *ecdsa.PublicKey, private *ecdsa.PrivateKey) error {
//
//	const predefinedMessage = "ECDSA key validation"
//	hash := sha256.Sum256([]byte(predefinedMessage))
//
//	r, s, err := ecdsa.Sign(rand.Reader, private, hash[:])
//	if err != nil {
//		return fmt.Errorf("%w: failed to sign message: %w", ErrSign, err)
//	}
//
//	if !ecdsa.Verify(public, hash[:], r, s) {
//		return fmt.Errorf("%w: invalid key pair: public and private keys do not match", ErrInvalidKeyPair)
//	}
//
//	return nil
//}
