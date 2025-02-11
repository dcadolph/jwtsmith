package jwt

import (
	"errors"
)

var (

	// ErrInvalidSigningMethod is returned when a signing method is not valid.
	ErrInvalidSigningMethod = errors.New("invalid signing method")

	// ErrEncode is returned when there is an error encoding something.
	ErrEncode = errors.New("encode failed")

	// ErrInvalidValue is returned when a value is not valid. Additional errors may
	// be wrapped for additional context. This is distinct from ErrInvalidType.
	ErrInvalidValue = errors.New("invalid value")

	// ErrGet is returned when there is a failure getting somethign.
	ErrGet = errors.New("get failed")
)
