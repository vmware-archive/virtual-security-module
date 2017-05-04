// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"testing"

	"github.com/vmware/virtual-security-module/config"
	"reflect"
)

var inMemoryDS *InMemoryDS

func inMemoryDSTestSetup() {
	tCfg := config.GenerateTestConfig()
	tCfg.DataStoreConfig.StoreType = inMemoryDSType

	inMemoryDS = NewInMemoryDS()
	inMemoryDS.Init(&tCfg.DataStoreConfig)
}

func inMemoryDSTestCleanup() {
}

func TestInMemoryDSCreateAndGet(t *testing.T) {
	id := "id1"

	dsEntry := &DataStoreEntry{
		Id:       id,
		Data:     []byte("data1"),
		MetaData: "metadata1",
	}

	if err := inMemoryDS.CreateEntry(dsEntry); err != nil {
		t.Fatalf("Failed to create entry: %v", err)
	}

	dsEntry2, err := inMemoryDS.ReadEntry(id)
	if err != nil {
		t.Fatalf("Failed to read entry: %v", err)
	}

	if !reflect.DeepEqual(dsEntry, dsEntry2) {
		t.Fatalf("Retreived value is different than expected")
	}

	if err := inMemoryDS.DeleteEntry(id); err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}
}

func TestInMemoryCreateDuplicate(t *testing.T) {
	id := "id1"

	dsEntry := &DataStoreEntry{
		Id:       id,
		Data:     []byte("data1"),
		MetaData: "metadata1",
	}

	if err := inMemoryDS.CreateEntry(dsEntry); err != nil {
		t.Fatalf("Failed to create entry: %v", err)
	}

	if err := inMemoryDS.CreateEntry(dsEntry); err == nil {
		t.Fatalf("Succeeded to create entry with an existing id")
	}

	if err := inMemoryDS.DeleteEntry(id); err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}
}

func TestInMemoryGetNonExistent(t *testing.T) {
	_, err := inMemoryDS.ReadEntry("non-existent-id")
	if err == nil {
		t.Fatalf("Succeeded to read entry with non-exietent id")
	}
}

func TestInMemoryDeleteNonExistent(t *testing.T) {
	err := inMemoryDS.DeleteEntry("non-existent-id")
	if err == nil {
		t.Fatalf("Succeeded to delete entry with non-exietent id")
	}
}

func TestInMemoryDSRecreateAfterDelete(t *testing.T) {
	id := "id1"

	dsEntry := &DataStoreEntry{
		Id:       id,
		Data:     []byte("data1"),
		MetaData: "metadata1",
	}

	if err := inMemoryDS.CreateEntry(dsEntry); err != nil {
		t.Fatalf("Failed to create entry: %v", err)
	}

	if err := inMemoryDS.DeleteEntry(id); err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}

	if err := inMemoryDS.CreateEntry(dsEntry); err != nil {
		t.Fatalf("Failed to create entry: %v", err)
	}

	dsEntry2, err := inMemoryDS.ReadEntry(id)
	if err != nil {
		t.Fatalf("Failed to read entry: %v", err)
	}

	if !reflect.DeepEqual(dsEntry, dsEntry2) {
		t.Fatalf("Retreived value is different than expected")
	}

	if err := inMemoryDS.DeleteEntry(id); err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}
}
