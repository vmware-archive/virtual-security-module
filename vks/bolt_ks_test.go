// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"os"
	"testing"

	"bytes"
	"github.com/vmware/virtual-security-module/config"
)

const testdbFilename = "testBoltKS.db"

var boltKS *BoltKS

func boltKSTestSetup() {
	tCfg := &config.KeyStoreConfig{
		StoreType:        boltKSType,
		ConnectionString: testdbFilename,
	}

	boltKS = NewBoltKS()
	boltKS.Init(tCfg)
}

func boltKSTestCleanup() {
	os.Remove(testdbFilename)
}

func TestBoltKSCreateAndGet(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := boltKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	val2, err := boltKS.Read(alias)
	if err != nil {
		t.Fatalf("Failed to read alias %s: %v", alias, err)
	}

	if !bytes.Equal(val, val2) {
		t.Fatalf("Retreived value %s is different than expected", string(val2))
	}

	if err := boltKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}

func TestBoltCreateDuplicate(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := boltKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	if err := boltKS.Create(alias, val); err == nil {
		t.Fatalf("Succeeded to create the same alias twice")
	}

	if err := boltKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}

func TestBoltGetNonExistent(t *testing.T) {
	alias := "alias1"

	_, err := boltKS.Read(alias)
	if err == nil {
		t.Fatalf("Succeeded to read a non-existing alias")
	}
}

func TestBoltDeleteNonExistent(t *testing.T) {
	alias := "alias1"

	err := boltKS.Delete(alias)
	if err == nil {
		t.Fatalf("Succeeded to delete a non-existing alias")
	}
}

func TestBoltKSRecreateAfterDelete(t *testing.T) {
	alias := "alias1"
	val := []byte("val1")

	if err := boltKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	if err := boltKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}

	if err := boltKS.Create(alias, val); err != nil {
		t.Fatalf("Failed to create alias %s: %v", alias, err)
	}

	val2, err := boltKS.Read(alias)
	if err != nil {
		t.Fatalf("Failed to read alias %s: %v", alias, err)
	}

	if !bytes.Equal(val, val2) {
		t.Fatalf("Retreived value %s is different than expected", string(val2))
	}

	if err := boltKS.Delete(alias); err != nil {
		t.Fatalf("Failed to delete alias %s: %v", alias, err)
	}
}
