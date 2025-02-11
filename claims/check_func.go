package claims

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// CheckFunc is used to verify claims.
type CheckFunc func(claims jwt.MapClaims) error

// CheckFuncNotEmptyExpiresAt returns a CheckFunc that ensures the "exp"
// claim is present and not empty or zero. It does not attempt to parse
// or validate the value beyond ensuring it is not nil, empty, or zero.
func CheckFuncNotEmptyExpiresAt() CheckFunc {
	return func(claims jwt.MapClaims) error {
		exp, ok := claims[KeyExpires]
		if !ok {
			return fmt.Errorf(
				"%w: expires at claim at key %s not found",
				ErrNotFound, KeyExpires,
			)
		}
		if exp == nil {
			return fmt.Errorf(
				"%w: expires at claim at key %s has nil value",
				ErrInvalidValue, KeyExpires,
			)
		}

		switch v := exp.(type) {
		case string:
			if v == "" {
				return fmt.Errorf(
					"%w: expires at claim at key %s is an empty string",
					ErrInvalidValue, KeyExpires,
				)
			}
		case int, int8, int16, int32, int64:
			if v == 0 {
				return fmt.Errorf(
					"%w: expires at claim at key %s is zero",
					ErrInvalidValue, KeyExpires,
				)
			}
		case float32, float64:
			if v == 0.0 {
				return fmt.Errorf(
					"%w: expires at claim at key %s is zero",
					ErrInvalidValue, KeyExpires,
				)
			}
		default:
			return fmt.Errorf(
				"%w: expires at claim at key %s is of unsupported type %T",
				ErrInvalidType, KeyExpires, exp,
			)
		}

		return nil
	}
}
