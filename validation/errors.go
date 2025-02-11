package validation

import (
	"errors"
)

var (

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
)
