// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"fmt"
	"sync"

	"github.com/vmware/virtual-security-module/config"
)

const dsType = "InMemoryDataStore"

func init() {
	if err := DataStoreRegistrar.Register(dsType, New()); err != nil {
		panic(fmt.Sprintf("Failed to register data store type %v: %v", dsType, err))
	}
}

// An implementation of a datastore in-memory.
// Useful for testing. Not recommended for production!!
type InMemoryDS struct {
	entryMap map[string]*DataStoreEntry
	mutex sync.Mutex
}

func New() *InMemoryDS {
	return &InMemoryDS {
		entryMap: make(map[string]*DataStoreEntry),
	}
}

func (ds *InMemoryDS) Init(map[string]*config.ConfigProperty) error {
	return nil
}

func (ds *InMemoryDS) CompleteInit(map[string]*config.ConfigProperty) error {
	return nil
}

func (ds *InMemoryDS) Initialized() bool {
	return true
}

func (ds *InMemoryDS) WriteEntry(entry *DataStoreEntry) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	ds.entryMap[entry.Id] = entry

	return nil
}

func (ds *InMemoryDS) ReadEntry(entryId string) (*DataStoreEntry, error) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	entry, ok := ds.entryMap[entryId]
	if !ok {
		return nil, fmt.Errorf("Entry with id %v not found", entryId)
	}

	return entry, nil
}

func (ds *InMemoryDS) DeleteEntry(entryId string) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	_, ok := ds.entryMap[entryId]
	if !ok {
		return fmt.Errorf("Entry with id %v not found", entryId)
	}

	delete(ds.entryMap, entryId)

	return nil
}

func (ds *InMemoryDS) Type() string {
	return dsType
}

func (ds *InMemoryDS) Location() string {
	return ""
}
