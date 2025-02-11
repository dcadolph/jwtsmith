package ecdsa

import (
	"errors"
)

var (

	// ErrExpired is returned when something is expired.
	ErrExpired = errors.New("expired")

	// ErrEncode is returned when there is an error encoding something.
	ErrEncode = errors.New("encode failed")

	// ErrInvalidType is returned when a type is not valid.
	ErrInvalidType = errors.New("invalid type")

	// ErrInvalidValue is returned when a value is not valid. Additional errors may
	// be wrapped for additional context. This is distinct from ErrInvalidType.
	ErrInvalidValue = errors.New("invalid value")

	// ErrGet is returned when there is a failure getting somethign.
	ErrGet = errors.New("get failed")

	// ErrParse is returned when there is an error parsing something.
	ErrParse = errors.New("parse failed")

	// ErrCheck is returned when there is a failure checking something/a check does not pass.
	ErrCheck = errors.New("check failed")

	// ErrNotReady is returned when a token is not ready.
	ErrNotReady = errors.New("not ready")

	// ErrSign is returned when there is an error signing something.
	ErrSign = errors.New("sign failed")

	// ErrInvalidKeyPair is returned when a public and private key are not valid pairs.
	ErrInvalidKeyPair = errors.New("invalid key pair")

	// ErrInvalidToken is returned when a token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidMethod is returned when a method is invalid.
	ErrInvalidMethod = errors.New("invalid method")

	// ErrInvalidSize is returned when there is an invalid size.
	ErrInvalidSize = errors.New("invalid size")
)
