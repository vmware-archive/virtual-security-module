// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

import (
	"crypto/rand"
	"math/big"
)

func randInt(limit *big.Int) *big.Int {
	res, _ := rand.Int(rand.Reader, limit)
	return res
}

func randPrime(numBits int) *big.Int {
	res, _ := rand.Prime(rand.Reader, numBits)
	return res
}
