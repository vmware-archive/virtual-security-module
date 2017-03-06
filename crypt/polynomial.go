// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

import "math/big"

//import "fmt"

type Polynomial struct {
	Coefs  []*big.Int
	Degree int
	Field  *big.Int
}

func NewPolynomial(secret *big.Int, degree int, field *big.Int) *Polynomial {
	p := new(Polynomial)
	p.Degree = degree
	p.Field = big.NewInt(0).Set(field)
	p.Coefs = make([]*big.Int, degree+1)

	p.Coefs[0] = big.NewInt(0).Set(secret)

	for i := 1; i <= degree; i++ {
		p.Coefs[i] = big.NewInt(0).Set(randInt(field))
	}

	return p
}

func (poly *Polynomial) Get(index int64) *big.Int {
	res := big.NewInt(0)

	//fmt.Printf("Base: %d\n", Index)
	//fmt.Printf("res: %s\n", Res.Text(10))

	for i := 0; i <= poly.Degree; i++ {
		exp := big.NewInt(int64(i))
		current := big.NewInt(0)
		current.Set(poly.Coefs[i])

		//fmt.Printf("Exp: %d\n", Index)
		//fmt.Printf("Base: %d\n", Index)

		x := big.NewInt(index)
		x.Exp(x, exp, poly.Field)

		current.Mul(current, x)
		res.Add(res, current)
		//fmt.Printf("res: %s\n", Res.Text(10))
	}
	return res.Mod(res, poly.Field)
}
