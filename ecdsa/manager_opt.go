package ecdsa

import (
	"github.com/dcadolph/jwtsmith/validation"
)

// ManagerOpts is a function type that modifies a managerECDSA.
type ManagerOpts func(*managerOpts)

type managerOpts struct {
	signerHeaders map[string]any

	tokenCheckFunc []validation.TokenCheckFunc
}

func WithTokenCheckFunc(cf ...validation.TokenCheckFunc) ManagerOpts {
	return func(m *managerOpts) {
		m.tokenCheckFunc = append(m.tokenCheckFunc, cf...)
	}
}

func WithTokenCheckFuncExclusive(cf ...validation.TokenCheckFunc) ManagerOpts {
	return func(m *managerOpts) {
		m.tokenCheckFunc = cf
	}
}
