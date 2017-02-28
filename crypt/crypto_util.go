// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

func GenerateKey() ([]byte, error) {
	return []byte("dummy-key"), nil
}

func Encrypt(data []byte, key []byte) ([]byte, error) {
	return data, nil
}

func Decrypt(data []byte, key []byte) ([]byte, error) {
	return data, nil
}

func BreakSecret(secret []byte, nGenerators int, minShares int) ([][]byte, error) {
	return [][]byte{}, nil
}

func ReconstructSecret(shares [][]byte) ([]byte, error) {
	return []byte{}, nil
}
