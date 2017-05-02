// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

func GenerateKey() ([]byte, error) {
	return generateKeyAES()
}

func Encrypt(data []byte, key []byte) ([]byte, error) {
	return encryptAES(data, key)
}

func Decrypt(data []byte, key []byte) ([]byte, error) {
	return decryptAES(data, key)
}
