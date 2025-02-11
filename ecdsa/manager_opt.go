package ecdsa

import (
	"github.com/dcadolph/jwtsmith/validation"
	"github.com/golang-jwt/jwt/v4"
)

// ManagerOpt is a function type that modifies a managerECDSA.
type ManagerOpt func(*managerOpt)

type managerOpt struct {
	signerHeaders      map[string]any
	signerStaticClaims jwt.MapClaims
	tokenCheckFunc     []validation.TokenCheckFunc
}

func WithSignerHeaders(signerHeaders map[string]any) ManagerOpt {
	return func(opt *managerOpt) {
		opt.signerHeaders = signerHeaders
	}
}

func WithSignerStaticClaims(signerStaticClaims jwt.MapClaims) ManagerOpt {
	return func(opt *managerOpt) {
		opt.signerStaticClaims = signerStaticClaims
	}
}

func WithTokenCheckFunc(cf ...validation.TokenCheckFunc) ManagerOpt {
	return func(m *managerOpt) {
		m.tokenCheckFunc = append(m.tokenCheckFunc, cf...)
	}
}

func WithTokenCheckFuncExclusive(cf ...validation.TokenCheckFunc) ManagerOpt {
	return func(m *managerOpt) {
		m.tokenCheckFunc = cf
	}
}
