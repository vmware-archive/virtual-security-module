// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"testing"

	"bytes"
	"github.com/vmware/virtual-security-module/config"
)

var vKeyStore *VirtualKeyStore

func vKeyStoreTestSetup() {
	tCfg := config.GenerateTestConfig()

	vKeyStore = NewVirtualKeyStore()
	vKeyStore.Init(tCfg)
}

func vKeyStoreTestCleanup() {
}

/*
func TestBreakSecretAndReconstruct(t *testing.T) {
	keyStores := vKeyStore.keyStores

	alias := "alias1"
	val := []byte("val1")

	shares := vKeyStore.secretSharer.BreakSecret(val)

	// write shares to key stores
	errors := make(chan error, len(shares))
	for i, share := range shares {
		fmt.Printf("Creating share in key store %v\n", i)
		createShareInKeyStore(keyStores[i], alias, share, errors)
	}

	// collect results
	for i := 0; i < len(shares); i++ {
		err := <-errors
		if err != nil {
			t.Fatalf("WARNING: failed to create alias %s in key store %v: %v\n", alias, i, err)
		} else {
			fmt.Printf("Created alias %s in key store %v\n", alias, i)
		}
	}
	close(errors)

	// read shares from key stores
	sharesCh := make(chan *crypt.SecretShare, vKeyStore.keyStoreCount)
	errors = make(chan error, vKeyStore.keyStoreCount)
	for i, ks := range keyStores {
		fmt.Printf("Reading share in key store %v\n", i)
		readShareFromKeyStore(ks, alias, sharesCh, errors)
	}

	// collect results
	shares2 := []*crypt.SecretShare{}
	for i := 0; i < vKeyStore.keyStoreCount; i++ {
		err := <-errors
		share := <-sharesCh
		if err != nil {
			t.Fatalf("WARNING: failed to read alias %s in key store %v: %v", alias, i, err)
		} else {
			shares2 = append(shares2, share)
			fmt.Printf("Read alias %s in key store %v\n", alias, i)
		}
	}
	close(errors)
	close(sharesCh)

	val2, err := vKeyStore.secretSharer.ReconstructSecret(shares)
	if err != nil {
		t.Fatalf("Failed to reconstruct secret: %v", err)
	}

	if !bytes.Equal(val, val2) {
		t.Fatalf("Reconstructed secret is different than original")
	}

}
*/

func TestVirtualKSCreateAndGet(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := vKeyStore.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	val2, err := vKeyStore.Read(alias)
	if err != nil {
		t.Fatalf("Failed to read alias %s: %v", alias, err)
	}

	if !bytes.Equal(val, val2) {
		t.Fatalf("Retreived value %s is different than expected", string(val2))
	}

	if err := vKeyStore.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}

func TestVirtualKSCreateDuplicate(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := vKeyStore.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	if err := vKeyStore.Create(alias, val); err == nil {
		t.Fatalf("Succeeded to create the same alias twice")
	}

	if err := vKeyStore.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}

func TestVirtualKSGetNonExistent(t *testing.T) {
	alias := "alias1"

	_, err := vKeyStore.Read(alias)
	if err == nil {
		t.Fatalf("Succeeded to read a non-existing alias")
	}
}

func TestVirtualKSDeleteNonExistent(t *testing.T) {
	alias := "alias1"

	err := vKeyStore.Delete(alias)
	if err == nil {
		t.Fatalf("Succeeded to delete a non-existing alias")
	}
}

func TestVirtualKSRecreateAfterDelete(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := vKeyStore.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	if err := vKeyStore.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}

	if err := vKeyStore.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	val2, err := vKeyStore.Read(alias)
	if err != nil {
		t.Fatalf("Failed to read alias %s: %v", alias, err)
	}

	if !bytes.Equal(val, val2) {
		t.Fatalf("Retreived value %s is different than expected", string(val2))
	}

	if err := vKeyStore.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}
