package crypt

import (
	"crypto/rand"
	"math/big"
)

func securerandom_rand_int(Limit *big.Int) *big.Int {
	Res, _ := rand.Int(rand.Reader, Limit)
	return Res
}

func securerandom_rand_prime(NumBits int) *big.Int {
	Res, _ := rand.Prime(rand.Reader, NumBits)
	return Res
}
