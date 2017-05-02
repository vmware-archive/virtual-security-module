// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"testing"

	"bytes"
	"github.com/vmware/virtual-security-module/config"
)

var inMemoryKS *InMemoryKS

func inMemoryKSTestSetup() {
	tCfg := &config.KeyStoreConfig{
		StoreType: inMemoryKSType,
	}

	inMemoryKS = NewInMemoryKS()
	inMemoryKS.Init(tCfg)
}

func inMemoryKSTestCleanup() {
}

func TestInMemoryKSCreateAndGet(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := inMemoryKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	val2, err := inMemoryKS.Read(alias)
	if err != nil {
		t.Fatalf("Failed to read alias %s: %v", alias, err)
	}

	if !bytes.Equal(val, val2) {
		t.Fatalf("Retreived value %s is different than expected", string(val2))
	}

	if err := inMemoryKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}

func TestInMemoryCreateDuplicate(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := inMemoryKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	if err := inMemoryKS.Create(alias, val); err == nil {
		t.Fatalf("Succeeded to create the same alias twice")
	}

	if err := inMemoryKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}

func TestInMemoryGetNonExistent(t *testing.T) {
	alias := "alias1"

	_, err := inMemoryKS.Read(alias)
	if err == nil {
		t.Fatalf("Succeeded to read a non-existing alias")
	}
}

func TestInMemoryDeleteNonExistent(t *testing.T) {
	alias := "alias1"

	err := inMemoryKS.Delete(alias)
	if err == nil {
		t.Fatalf("Succeeded to delete a non-existing alias")
	}
}

func TestInMemoryKSRecreateAfterDelete(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := inMemoryKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	if err := inMemoryKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}

	if err := inMemoryKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	val2, err := inMemoryKS.Read(alias)
	if err != nil {
		t.Fatalf("Failed to read alias %s: %v", alias, err)
	}

	if !bytes.Equal(val, val2) {
		t.Fatalf("Retreived value %s is different than expected", string(val2))
	}

	if err := inMemoryKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}
