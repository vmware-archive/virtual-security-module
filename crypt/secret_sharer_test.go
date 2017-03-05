package crypt

import (
    "testing"
    "bytes"
)

func TestSecretSharer(t *testing.T) {
	message := "this is some test message to be broken and reconstructed"
	secret := []byte(message)
	
	n := 10
	k := 3

	ss := secret_sharer_create_randfield(2048, n, k)
	
	shares := secret_sharer_break_secret(ss, secret)
	
	data, err := secret_sharer_reconstruct_secret(ss, shares[:k])
	
	if err != nil {
		t.Fatalf("Failed to reconstruct secret: %s", err.Error())
	}
	
	if data == nil {
		t.Fatal("Secret sharer test failed - returned nil")
	}
	
	if !bytes.Equal(secret, data) {
		t.Fatal("Reconstructed data differs from secret")
	}
}

