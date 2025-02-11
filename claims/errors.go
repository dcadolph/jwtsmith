package claims

import (
	"errors"
)

var (

	// ErrInvalidType is returned when a type is not valid.
	ErrInvalidType = errors.New("invalid type")

	// ErrInvalidValue is returned when a value is not valid. Additional errors may
	// be wrapped for additional context. This is distinct from ErrInvalidType.
	ErrInvalidValue = errors.New("invalid value")

	// ErrNotFound is returned when something is not found.
	ErrNotFound = errors.New("not found")
)
