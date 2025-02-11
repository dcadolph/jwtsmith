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
)
