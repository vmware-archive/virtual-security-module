package crypt

import (
	"bytes"
	"errors"
	"math/big"
	"crypto/sha256"
)

type SecretSharer struct {
	Field *big.Int
	n int
	k int
}

type SecretShare struct {
	Index int
	Value *big.Int
	Field *big.Int
	Version int
}

func factorial(n int) *big.Int {
	Current := new(big.Int).SetInt64(1)
	
	for i := 2; i <= n; i++ {
		Current.Mul(Current, big.NewInt(int64(i)))
	}
	return Current
}

func secret_sharer_create_randfield(numBits int, n int, k int) *SecretSharer {
	ss := new(SecretSharer)
	ss.Field = securerandom_rand_prime(numBits)
	ss.n = n
	ss.k = k
	return ss
}

func secret_sharer_create(Field *big.Int, n int, k int) *SecretSharer {
	ss := new(SecretSharer)
	ss.Field = new(big.Int).Set(Field)
	ss.n = n
	ss.k = k
	return ss
}

func secret_sharer_break_secret(s *SecretSharer, secret []byte) []*SecretShare {
	bin := make([]byte, len(secret) + sha256.Size)
	copy(bin[:len(secret)], secret)
	sha := sha256.Sum256(secret)
	copy(bin[len(secret):], sha[:])
	bn := new(big.Int)
	bn.SetBytes(bin)
	
	Poly := polynomial_create(bn, s.k - 1, s.Field)
	
	res := make([]*SecretShare, s.n)
	
	for i := 1; i <= s.n; i++ {
		// Create shares
		res[i - 1] = secret_share_create(i, polynomial_get(Poly, int64(i)), 1, s.Field)
	}
	
	return res
}

func lambda(index int64, i int, x_values []int, k int, field *big.Int) *big.Rat {
	resN := int64(1)
	resD := int64(1)
	xi := int64(x_values[i])
	
	for j := 0; j < k; j++ {
		if j == i { continue }
		xk := int64(x_values[j])
		resN = (resN * (index - xk))
		resD = (resD * (xi - xk))
	}
	res := new(big.Rat)
	res.SetFrac64(resN, resD)
	return res
}

func integrate(index int64, shares []*SecretShare, k int, field *big.Int) (*big.Int, error) {
	x_values := make([]int, k)
	// Init list of indexes
	for i := 0; i < k; i++ {
		x_values[i] = shares[i].Index
	}

	res := big.NewRat(0, 1)
	for i := 0; i < k; i++ {
		lambda_res := lambda(index, i, x_values, k, field);
		share := big.NewRat(0, 1).SetInt(shares[i].Value)
		lambda_res.Mul(lambda_res, share)
		res.Add(res, lambda_res)
	}
	
	if !res.IsInt() {
		// Integration failed, as the result is not an integer
		return nil, errors.New("Share integration failed")
	}
	
	num := res.Num()
	num.Mod(num, field)
	
	return num, nil
}

func secret_sharer_reconstruct_secret(s *SecretSharer, shares []*SecretShare) ([]byte, error) {
	// Check that all shares have the same field
	field := shares[0].Field

	for i := 1; i < len(shares); i++ {
		if field.Cmp(shares[i].Field) != 0 {
			// Error: Field mismatch
			return nil, errors.New("Shares must have the same field")
		}
	}

	resnum, err := integrate(0, shares, s.k, field)
	if err != nil {
		return nil, err
	}

	// Convert resnum to bytes
	bin := resnum.Bytes()

	// Verification
	if (len(bin) <= sha256.Size) {
		// Error: Return value is too short
		return nil, errors.New("Reconstruction result is too short")
	}

	reslen := len(bin) - sha256.Size
	hash := bin[reslen:]
	data := bin[:reslen]
	newHash := sha256.Sum256(data)

	if (!bytes.Equal(hash, newHash[:])) {
		// Error: Hash does not match
		return nil, errors.New("Reconstruction result is wrong")
	}

	return data, nil
}

func secret_share_create(index int, value *big.Int, version int, field *big.Int) *SecretShare {
	s := new(SecretShare)
	s.Index = index
	s.Value = new(big.Int)
	s.Value.Set(value)
	s.Field = new(big.Int)
	s.Field.Set(field)
	s.Version = version
	return s
}
