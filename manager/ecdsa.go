package manager

//
//import (
//	"crypto/ecdsa"
//	"fmt"
//
//	"github.com/dcadolph/jwtsmith/validation"
//	"github.com/golang-jwt/jwt/v4"
//)
//
//// ECDSAManagerOpts is a function type that modifies a managerECDSA.
//type ECDSAManagerOpts func(*managerECDSA)
//
//type managerECDSA struct {
//	validation.TokenValidator
//	pubKey         *ecdsa.PublicKey
//	privateKey     *ecdsa.PrivateKey
//	tokenCheckFunc []validation.TokenCheckFunc
//	// TODO: Identify additional ECDSAManagerOpts fields that would make sense, such as "static claims" perhaps, which could be claims added to every token or something.
//}
//
//func NewManagerECSDA(signingMethod jwt.SigningMethod, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, opts ...ECDSAManagerOpts) (Manager, error) {
//
//	mgr := &managerECDSA{}
//	for _, opt := range opts {
//		opt(mgr)
//	}
//
//	validator, err := validation.ECDSAValidator(signingMethod, publicKey, mgr.tokenCheckFunc...)
//	if err != nil {
//		return nil, fmt.Errorf("NewManagerECSDA: %w", err) // IMPROVE ME
//	}
//	mgr.TokenValidator = validator
//
//	return mgr, nil
//}
//
//func WithTokenCheckFunc(cf ...validation.TokenCheckFunc) ECDSAManagerOpts {
//	return func(m *managerECDSA) {
//		m.tokenCheckFunc = cf
//	}
//}
