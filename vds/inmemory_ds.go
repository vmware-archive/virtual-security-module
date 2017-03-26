// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"fmt"
	"path"
	"sync"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/util"
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
	mutex    sync.Mutex
}

func New() *InMemoryDS {
	return &InMemoryDS{
		entryMap: make(map[string]*DataStoreEntry),
	}
}

func (ds *InMemoryDS) Init(*config.Config) error {
	return nil
}

func (ds *InMemoryDS) CompleteInit(*config.Config) error {
	return nil
}

func (ds *InMemoryDS) Initialized() bool {
	return true
}

func (ds *InMemoryDS) WriteEntry(entry *DataStoreEntry) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	buf := make([]byte, len(entry.Data))
	copy(buf, entry.Data)

	dsEntry := &DataStoreEntry{
		Id:       entry.Id,
		Data:     buf,
		MetaData: entry.MetaData,
	}

	ds.entryMap[entry.Id] = dsEntry

	return nil
}

func (ds *InMemoryDS) ReadEntry(entryId string) (*DataStoreEntry, error) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	entry, ok := ds.entryMap[entryId]
	if !ok {
		return nil, util.ErrNotFound
	}

	buf := make([]byte, len(entry.Data))
	copy(buf, entry.Data)

	dsEntry := &DataStoreEntry{
		Id:       entry.Id,
		Data:     buf,
		MetaData: entry.MetaData,
	}

	return dsEntry, nil
}

func (ds *InMemoryDS) DeleteEntry(entryId string) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	_, ok := ds.entryMap[entryId]
	if !ok {
		return util.ErrNotFound
	}

	delete(ds.entryMap, entryId)

	return nil
}

func (ds *InMemoryDS) SearchEntries(entryIdPattern string) ([]*DataStoreEntry, error) {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	dsEntries := make([]*DataStoreEntry, 0)

	for entryId, entry := range ds.entryMap {
		matched, err := path.Match(entryIdPattern, entryId)
		if err != nil {
			return dsEntries, err
		}

		if matched {
			buf := make([]byte, len(entry.Data))
			copy(buf, entry.Data)

			dsEntry := &DataStoreEntry{
				Id:       entry.Id,
				Data:     buf,
				MetaData: entry.MetaData,
			}

			dsEntries = append(dsEntries, dsEntry)
		}
	}

	return dsEntries, nil
}

func (ds *InMemoryDS) Type() string {
	return dsType
}

func (ds *InMemoryDS) Location() string {
	return ""
}
