// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"github.com/vmware/virtual-security-module/config"
)

const (
	PropertyNameDataStore     = "dataStore"
	PropertyNameDataStoreType = "type"
)

type DataStoreEntry struct {
	Id       string
	Data     []byte
	MetaData string
}

type DataStoreAdapter interface {
	Init(*config.DataStoreConfig) error
	CompleteInit(*config.DataStoreConfig) error
	Initialized() bool

	CreateEntry(entry *DataStoreEntry) error
	ReadEntry(entryId string) (*DataStoreEntry, error)
	DeleteEntry(entryId string) error
	SearchChildEntries(parentEntryId string) ([]*DataStoreEntry, error)

	Type() string
	Location() string
}
