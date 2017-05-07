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
