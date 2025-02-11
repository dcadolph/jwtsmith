package claims

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
)

// TestTimestamp tests Timestamp in various scenarios.
func TestTimestamp(t *testing.T) {

	t.Parallel()

	testTable := []struct {
		Input           any
		WantNumericDate *jwt.NumericDate
		Want            error
	}{
		{ // Test 0: Valid jwt.NumericDate
			Input:           jwt.NewNumericDate(time.Unix(1609459200, 0)), // 2021-01-01 00:00:00 UTC
			WantNumericDate: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 1: Nil *jwt.NumericDate
			Input: (*jwt.NumericDate)(nil),
			Want:  ErrInvalidValue,
		},
		{ // Test 2: Valid *jwt.NumericDate
			Input:           jwt.NewNumericDate(time.Unix(1609459200, 0)),
			WantNumericDate: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 3: Zero-value jwt.NumericDate
			Input: jwt.NumericDate{},
			Want:  ErrInvalidValue,
		},
		{ // Test 4: Nil *float64
			Input: (*float64)(nil),
			Want:  ErrInvalidValue,
		},
		{ // Test 5: Valid float64
			Input:           1609459200.123456, // 2021-01-01 00:00:00.123456 UTC
			WantNumericDate: jwt.NewNumericDate(time.Unix(1609459200, 123456000)),
		},
		{ // Test 6: Invalid float64 (less than 1)
			Input: 0.5,
			Want:  ErrInvalidValue,
		},
		{ // Test 7: Nil *time.Time
			Input: (*time.Time)(nil),
			Want:  ErrInvalidValue,
		},
		{ // Test 8: Valid time.Time
			Input:           time.Unix(1609459200, 0),
			WantNumericDate: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 9: Zero-value time.Time
			Input: time.Time{},
			Want:  ErrInvalidValue,
		},
		{ // Test 10: Nil *int64
			Input: (*int64)(nil),
			Want:  ErrInvalidValue,
		},
		{ // Test 11: Valid int64
			Input:           int64(1609459200), // 2021-01-01 00:00:00 UTC
			WantNumericDate: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 12: Valid int
			Input:           1609459200, // 2021-01-01 00:00:00 UTC
			WantNumericDate: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 13: Unsupported type
			Input: "2021-01-01T00:00:00Z",
			Want:  ErrInvalidType,
		},
	}

	for testNum, test := range testTable {
		t.Run(fmt.Sprintf("Test %d", testNum+1), func(t *testing.T) {

			t.Parallel()

			got, err := Timestamp(test.Input)
			if !errors.Is(err, test.Want) {
				t.Fatalf("test %d: error mismatch\nWant: %v\nGot: %v", testNum, test.Want, err)
			}

			// Nothing more to do.
			if err != nil {
				return
			}

			if diff := cmp.Diff(test.WantNumericDate, got); diff != "" {
				t.Fatalf("Test %d: Timestamp() mismatch (-want +got):\n%s", testNum+1, diff)
			}
		})
	}
}
