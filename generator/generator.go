package generator

import (
	"github.com/golang-jwt/jwt/v4"
)

type Generator interface {
	GenerateToken() (*jwt.Token, error)
}
