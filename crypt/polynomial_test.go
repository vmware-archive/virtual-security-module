// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

import (
	"math/big"
	"testing"
)

func TestPolynomial(t *testing.T) {
	secret := big.NewInt(123456)
	degree := 3
	field := big.NewInt(0)
	field.SetString("1066340417491710595814572169", 10)
	poly := NewPolynomial(secret, degree, field)

	for x := 0; x < 100; x++ {
		v := poly.Get(int64(x))
		v1 := big.NewInt(0)
		for i := 0; i <= poly.Degree; i++ {
			exp := big.NewInt(int64(i))
			current := big.NewInt(0).Set(poly.Coefs[i])
			base := big.NewInt(int64(x))
			current.Mul(current, base.Exp(base, exp, poly.Field))
			v1.Add(v1, current)
		}
		v1.Mod(v1, poly.Field)
		if v.Cmp(v1) != 0 {
			t.Fatalf("polynomial_get returns unexpected result (expected: %s, actual: %s)", v1.Text(10), v.Text(10))
		}
	}
}
