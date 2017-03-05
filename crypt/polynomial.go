package crypt

import "math/big"
//import "fmt"

type Polynomial struct {
	Coefs []*big.Int
	Degree int
	Field *big.Int
}

func polynomial_create(Secret *big.Int, Degree int, Field *big.Int) *Polynomial {
	p := new(Polynomial)
	p.Degree = Degree
	p.Field = new(big.Int).Set(Field)
	p.Coefs = make([]*big.Int, Degree + 1)
	
	p.Coefs[0] = new(big.Int).Set(Secret)
	
	for i := 1; i <= Degree; i++ {
		p.Coefs[i] = new(big.Int).Set(securerandom_rand_int(Field))
	}
	
	return p
}

func polynomial_get(Poly *Polynomial, Index int64) *big.Int {
	Res := big.NewInt(0)
	
	//fmt.Printf("Base: %d\n", Index)
	//fmt.Printf("res: %s\n", Res.Text(10))
	
	for i := 0; i <= Poly.Degree; i++ {
		Exp := big.NewInt(int64(i))
		Current := new(big.Int)
		Current.Set(Poly.Coefs[i])

		//fmt.Printf("Exp: %d\n", Index)
		//fmt.Printf("Base: %d\n", Index)
		
		x := big.NewInt(Index)
		x.Exp(x, Exp, Poly.Field)

		Current.Mul(Current, x)
		Res.Add(Res, Current)
		//fmt.Printf("res: %s\n", Res.Text(10))
	}
	return Res.Mod(Res, Poly.Field)
}
