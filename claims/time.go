package claims

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Timestamp takes a given interface value and returns it as a *jwt.NumericDate.
// This function is useful for parsing timestamps in claims when the value is
// provided as an interface (any). If the underlying value is already a reference
// to a jwt.NumericDate, a copy of it is returned based on its underlying time.Time.
//
// Standard claims like "exp" (expires-at) are typically of type jwt.NumericDate,
// but this is not guaranteed. Additionally, there may be custom claims that
// use timestamps without leveraging jwt.NumericDate. By converting the claim's
// timestamp to a jwt.NumericDate, consumers can ensure consistent comparison
// and inspection of times across different claims, regardless of the original
// format of the timestamp.
func Timestamp(ts any) (*jwt.NumericDate, error) {

	switch v := ts.(type) {

	// We typically expect a jwt.NumericDate or reference to one in a claim.
	case *jwt.NumericDate:
		if v == nil {
			return nil, fmt.Errorf(
				"%w: invalid value for jwt.NumericDate: nil pointer",
				ErrInvalidValue,
			)
		}
		if v.IsZero() {
			return nil, fmt.Errorf(
				"%w: invalid value for jwt.NumericDate: time.Time is zero-value",
				ErrInvalidValue,
			)
		}

		return jwt.NewNumericDate(v.Time), nil

	case jwt.NumericDate:
		if v.IsZero() {
			return nil, fmt.Errorf(
				"%w: invalid value for jwt.NumericDate: time.Time is zero-value",
				ErrInvalidValue,
			)
		}
		return jwt.NewNumericDate(v.Time), nil

	case *float64:
		if v == nil {
			return nil, fmt.Errorf(
				"%w: invalid value for float64: nil pointer",
				ErrInvalidValue,
			)
		}
		return TimeFromFloat(*v)

	case float64:
		return TimeFromFloat(v)

	case *time.Time:
		if v == nil {
			return nil, fmt.Errorf(
				"%w: invalid value for time.Time: nil pointer",
				ErrInvalidValue,
			)
		}
		if v.IsZero() {
			return nil, fmt.Errorf(
				"%w: invalid value for time.Time: time.Time is zero-value",
				ErrInvalidValue,
			)
		}
		return jwt.NewNumericDate(*v), nil

	case time.Time:
		if v.IsZero() {
			return nil, fmt.Errorf(
				"%w: invalid value for time.Time: time.Time is zero-value",
				ErrInvalidValue,
			)
		}
		return jwt.NewNumericDate(v), nil

	case json.Number:
		if i64, err := v.Int64(); err == nil {
			return TimeFromFloat(float64(i64))
		} else if f64, err := v.Float64(); err == nil {
			return TimeFromFloat(f64)
		} else {
			return nil, fmt.Errorf("%w: invalid json.Number: %v", ErrInvalidValue, err)
		}

	case *string:
		if v == nil {
			return nil, fmt.Errorf("%w: invalid value for string: nil pointer", ErrInvalidValue)
		}
		return parseStringToNumericDate(*v)

	case string:
		return parseStringToNumericDate(v)

	case *int64:
		if v == nil {
			return nil, fmt.Errorf(
				"%w: invalid value for int64: nil pointer",
				ErrInvalidValue,
			)
		}
		return TimeFromFloat(float64(*v))

	case int64:
		return TimeFromFloat(float64(v))

	case *int:
		if v == nil {
			return nil, fmt.Errorf(
				"%w: invalid value for int: nil pointer",
				ErrInvalidValue,
			)
		}
		return TimeFromFloat(float64(*v))

	case int:
		return TimeFromFloat(float64(v))

	default:
		return nil, fmt.Errorf("%w: unsupported type %T", ErrInvalidType, ts)
	}
}

// parseStringToNumericDate tries to parse a string to a time.Time and then returns a jwt.NumericDate.
func parseStringToNumericDate(s string) (*jwt.NumericDate, error) {

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return jwt.NewNumericDate(t), nil
	}

	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return TimeFromFloat(f)
	}

	return nil, fmt.Errorf("%w: invalid string format for timestamp: %s", ErrInvalidValue, s)
}

// TimeFromFloat converts a float to a jwt.NumericDate, preserving the precision by converting
// the integer part to seconds and the fractional part to nanoseconds. This ensures that any
// sub-second precision represent in the original value is accurately represented in the
// resulting time.Time and subsequently in the jwt.NumericDate.
func TimeFromFloat(v float64) (*jwt.NumericDate, error) {

	if v < 1 {
		return nil, fmt.Errorf(
			"%w: invalid value: time value is less than 1",
			ErrInvalidValue,
		)
	}

	seconds := int64(v)
	fractionalSeconds := v - float64(seconds)

	return jwt.NewNumericDate(time.Unix(seconds, int64(fractionalSeconds*1e9))), nil
}
