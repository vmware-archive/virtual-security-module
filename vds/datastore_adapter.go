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
	Init(*config.Config) error
	CompleteInit(*config.Config) error
	Initialized() bool

	WriteEntry(entry *DataStoreEntry) error
	ReadEntry(entryId string) (*DataStoreEntry, error)
	DeleteEntry(entryId string) error
	SearchChildEntries(parentEntryId string) ([]*DataStoreEntry, error)

	Type() string
	Location() string
}
