package manager

import (
	"github.com/dcadolph/jwtsmith/refresher"
	"github.com/dcadolph/jwtsmith/validation"
)

// TODO: methods to add claims, modify, remove (requires resign), means of making new token, means of actually having the manager create public and proviate key for them
type Manager interface {
	validation.TokenValidator
	refresher.Refresher
}

//
//type manager struct {
//	validator  validation.TokenValidator
//	pubKey     *ecdsa.PublicKey
//	privateKey *ecdsa.PrivateKey
//}
