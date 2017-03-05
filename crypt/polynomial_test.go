package crypt

import (
	"math/big"
    "testing"
)

func TestPolynomial(t *testing.T) {
	Secret := big.NewInt(123456)
	Degree := 3
	Field := new(big.Int)
	Field.SetString("1066340417491710595814572169", 10)
	Poly := polynomial_create(Secret, Degree, Field)
	
	for x := 0; x < 100000; x++ {
		v := polynomial_get(Poly, int64(x))
		v1 := big.NewInt(0)
		for i := 0; i <= Poly.Degree; i++ {
			Exp := big.NewInt(int64(i))
			Current := new(big.Int)
			Current.Set(Poly.Coefs[i])
			Base := big.NewInt(int64(x))
			Current.Mul(Current, Base.Exp(Base, Exp, Poly.Field))
			v1.Add(v1, Current)
		}
		v1.Mod(v1, Poly.Field)
		if (v.Cmp(v1) != 0) {
			t.Fatalf("polynomial_get returns unexpected result (expected: %s, actual: %s)", v1.Text(10), v.Text(10))
		}
	}
}

