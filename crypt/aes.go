package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"fmt"
	"encoding/binary"
	"crypto/sha256"
	"bytes"
)

func createKey() []byte {
	return randPrime(256).Bytes()
}

func encrypt(key []byte, data []byte) []byte {
	// Compute hash
	sha := sha256.Sum256(data)

	// Append size
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	data = append(b, data...)

	// Append hash
	data = append(data, sha[:]...)

	// Padding
	if len(data) % aes.BlockSize != 0 {
		// TODO: This padding is simple padding, might not be the most secure way to do that
		toadd := aes.BlockSize - (len(data) % aes.BlockSize)
		data = append(data, make([]byte, toadd)...)
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Add random IV to ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

	return ciphertext
}

func decrypt(key []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	mode.CryptBlocks(plaintext, ciphertext)

	size := binary.BigEndian.Uint32(plaintext[:4])
	if len(plaintext) < (4 + int(size) + sha256.Size) {
		panic(fmt.Sprintf("result too short (size=%d, len=%d)", size, len(plaintext)))
	}
	
	data := plaintext[4:4+size]
	sha := plaintext[4+size:4+size+sha256.Size]
	
	newSha := sha256.Sum256(data)
	if !bytes.Equal(sha, newSha[:]) {
		panic("Hash does not match")
	}
	
	return data
}