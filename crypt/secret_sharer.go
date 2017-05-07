// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"sort"
)

/////// Share sorting ////////
type By func(p1, p2 *SecretShare) bool

func (by By) Sort(shares []*SecretShare) {
	ps := &shareSorter{
		shares: shares,
		by:     by,
	}
	sort.Sort(ps)
}

type shareSorter struct {
	shares []*SecretShare
	by     func(p1, p2 *SecretShare) bool
}

func (s *shareSorter) Len() int {
	return len(s.shares)
}

func (s *shareSorter) Swap(i, j int) {
	s.shares[i], s.shares[j] = s.shares[j], s.shares[i]
}

func (s *shareSorter) Less(i, j int) bool {
	return s.by(s.shares[i], s.shares[j])
}

/////// End of share sorting ////////

type SecretSharer struct {
	field *big.Int
	n     int
	k     int
}

type SecretShare struct {
	Index   int
	Value   *big.Int
	Field   *big.Int
	Version int
}

func factorial(n int) *big.Int {
	current := big.NewInt(1)

	for i := 2; i <= n; i++ {
		current.Mul(current, big.NewInt(int64(i)))
	}
	return current
}

func NewSecretSharerRandField(numBits int, n int, k int) *SecretSharer {
	ss := new(SecretSharer)
	ss.field = randPrime(numBits)
	ss.n = n
	ss.k = k
	return ss
}

func NewSecretSharer(field *big.Int, n int, k int) *SecretSharer {
	ss := new(SecretSharer)
	ss.field = big.NewInt(0).Set(field)
	ss.n = n
	ss.k = k
	return ss
}

func (s *SecretSharer) BreakSecret(secret []byte) []*SecretShare {
	bin := make([]byte, len(secret)+sha256.Size)
	copy(bin, secret)
	sha := sha256.Sum256(secret)
	copy(bin[len(secret):], sha[:])
	bn := big.NewInt(0).SetBytes(bin)

	poly := NewPolynomial(bn, s.k-1, s.field)

	res := make([]*SecretShare, s.n)

	for i := 1; i <= s.n; i++ {
		// Create shares
		res[i-1] = NewSecretShare(i, poly.Get(int64(i)), 1, s.field)
	}

	return res
}

func lambda(index int64, i int, x_values []int, k int, field *big.Int) *big.Rat {
	resN := int64(1)
	resD := int64(1)
	xi := int64(x_values[i])

	for j := 0; j < k; j++ {
		if j == i {
			continue
		}
		xk := int64(x_values[j])
		resN = (resN * (index - xk))
		resD = (resD * (xi - xk))
	}
	res := big.NewRat(resN, resD)
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
		lambda_res := lambda(index, i, x_values, k, field)
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

func (s *SecretSharer) ReconstructSecret(shares []*SecretShare) ([]byte, error) {
	// Check that all shares have the same field
	if len(shares) < 2 {
		return nil, errors.New("Expected at least two shares")
	}
	field := shares[0].Field

	for i := 1; i < len(shares); i++ {
		if field.Cmp(shares[i].Field) != 0 {
			// Error: Field mismatch
			return nil, errors.New("Shares must have the same field")
		}
	}

	// Sort shares
	share_sort_func := func(s1, s2 *SecretShare) bool {
		return s1.Index < s2.Index
	}
	By(share_sort_func).Sort(shares)

	resnum, err := integrate(0, shares, s.k, field)
	if err != nil {
		return nil, err
	}

	// Convert resnum to bytes
	bin := resnum.Bytes()

	// Verification
	if len(bin) <= sha256.Size {
		// Error: Return value is too short
		return nil, errors.New("Reconstruction result is too short")
	}

	reslen := len(bin) - sha256.Size
	hash := bin[reslen:]
	data := bin[:reslen]
	newHash := sha256.Sum256(data)

	if !bytes.Equal(hash, newHash[:]) {
		// Error: Hash does not match
		return nil, errors.New("Reconstruction result is wrong")
	}

	return data, nil
}

func NewSecretShare(index int, value *big.Int, version int, field *big.Int) *SecretShare {
	s := new(SecretShare)
	s.Index = index
	s.Value = big.NewInt(0).Set(value)
	s.Field = big.NewInt(0).Set(field)
	s.Version = version
	return s
}
