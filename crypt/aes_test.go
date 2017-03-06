// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package crypt

import (
    "testing"
    "bytes"
    "strings"
)

func TestAES(t *testing.T) {
	data := "this is some long message we would like to encrypt and then decrypt"
	bin := []byte(data)
	
	key, _ := GenerateKey()
	
	encrypted, err := Encrypt(bin, key)
	if err != nil {
		t.Fatal(err)
	}
	
	if bytes.Equal(bin, encrypted) {
		t.Fatal("Encrypted is same as input")
	}
	
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	
	if !bytes.Equal(decrypted, bin) {
		t.Fatalf("Decrypted data differs from input (expected: %v, actual: %v)", bin, decrypted)
	}
	
	str := string(decrypted)
	
	if strings.Compare(str, data) != 0 {
		t.Fatalf("Decrypted text differs from input (expected: %s, actual: %s)", data, str)
	}

}

