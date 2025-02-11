package validation

import (
	"io"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/golang-jwt/jwt/v4"
)

type TokenCheckFunc func(token *jwt.Token, checkFunc ...claims.CheckFunc) error

func TokenCheckFuncClaimsCheck(claimsCheck ...claims.CheckFunc) TokenCheckFunc {
	return func(token *jwt.Token, checkFunc ...claims.CheckFunc) error {
		if len(claimsCheck) == 0 {
			return nil
		}
		mapClaims, mapClaimsErr := claims.ToMapClaims(token.Claims)
		if mapClaimsErr != nil {
			return mapClaimsErr // WRAP ME.
		}
		for _, checkFunc := range claimsCheck {
			if err := checkFunc(mapClaims); err != nil {
				return err // TODO wrap me
			}
		}
		return nil
	}
}

func TokenCheckFuncBannedHeaders(bannedHeaders ...string) TokenCheckFunc {
	return func(token *jwt.Token, checkFunc ...claims.CheckFunc) error {
		for _, banned := range bannedHeaders {
			if _, ok := token.Header[banned]; ok {
				return io.EOF // TODO Obviously improve me
			}
		}
		return nil
	}
}

func TokenCheckFuncRequiredHeaders(requiredHeaders ...string) TokenCheckFunc {
	return func(token *jwt.Token, checkFunc ...claims.CheckFunc) error {
		for _, required := range requiredHeaders {
			if _, ok := token.Header[required]; !ok {
				return io.EOF // TODO Obviously improve me
			}
		}
		return nil
	}
}

func TokenCheckFuncRequiredHeaderValues(requiredHeaderValues map[string]any) TokenCheckFunc {
	return func(token *jwt.Token, checkFunc ...claims.CheckFunc) error {
		for requiredHeader, requiredVal := range requiredHeaderValues {
			if headerValue, ok := token.Header[requiredHeader]; !ok {
				return io.EOF // Improve.
			} else if headerValue != requiredVal { // TODO this may not be good enough
				return io.EOF
			}
		}
		return nil
	}
}
