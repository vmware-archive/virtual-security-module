package crypt

import (
	"crypto/rand"
	"math/big"
)

func randInt(Limit *big.Int) *big.Int {
	Res, _ := rand.Int(rand.Reader, Limit)
	return Res
}

func randPrime(NumBits int) *big.Int {
	Res, _ := rand.Prime(rand.Reader, NumBits)
	return Res
}
