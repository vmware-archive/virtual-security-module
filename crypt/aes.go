// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func generateKeyAES() ([]byte, error) {
	return randPrime(256).Bytes(), nil
}

func encryptAES(data []byte, key []byte) ([]byte, error) {
	// Compute hash
	sha := sha256.Sum256(data)

	// Append size
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	data = append(b, data...)

	// Append hash
	data = append(data, sha[:]...)

	// Padding
	if len(data)%aes.BlockSize != 0 {
		// TODO: This padding is simple padding, might not be the most secure way to do that
		toadd := aes.BlockSize - (len(data) % aes.BlockSize)
		data = append(data, make([]byte, toadd)...)
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Add random IV to ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	mode.CryptBlocks(plaintext, ciphertext)

	size := binary.BigEndian.Uint32(plaintext[:4])
	if len(plaintext) < (4 + int(size) + sha256.Size) {
		return nil, errors.New(fmt.Sprintf("result too short (size=%d, len=%d)", size, len(plaintext)))
	}

	data := plaintext[4 : 4+size]
	sha := plaintext[4+size : 4+size+sha256.Size]

	newSha := sha256.Sum256(data)
	if !bytes.Equal(sha, newSha[:]) {
		return nil, errors.New("Hash does not match")
	}

	return data, nil
}
