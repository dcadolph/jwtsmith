package refresher

import (
	"github.com/golang-jwt/jwt/v4"
)

// Refresher refreshes JWT.
type Refresher interface {
	// Refresh should refresh the given JWT.
	//
	// Token should either be type string (a signed token string) or
	// *jwt.Token, which the Refresher is capable of signing. Both the
	// *jwt.Token and signed string are returned to the caller. The
	// former gives the caller the option to further modify the *jwt.Token
	// before signing it, while the latter makes it possible to directly
	// take the value from the Refresh call and pass it to the intended target.
	Refresh(token any) (*jwt.Token, string, error)
}

// Func is used to convert function literals to Refresher.
type Func func(token any) (*jwt.Token, string, error)

// Refresh calls the receiver, implementing Refresher.
func (f Func) Refresh(token any) (*jwt.Token, string, error) {
	return f(token)
}
