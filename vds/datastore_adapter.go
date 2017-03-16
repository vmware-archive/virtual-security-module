// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"github.com/vmware/virtual-security-module/config"
)

const (
	PropertyNameDataStore            = "dataStore"
	PropertyNameDataStoreType        = "dataStoreType"
	PropertyNameDataStoreLocation    = "dataStoreLocation"
	PropertyNameDataStoreCredentials = "dataStoreCredentials"
	PropertyNameOutOfBandInit        = "dataStoreOutOfBandInit"
)

type DataStoreEntry struct {
	Id       string
	Data     []byte
	MetaData string
}

type DataStoreAdapter interface {
	Init(map[string]*config.ConfigProperty) error
	CompleteInit(map[string]*config.ConfigProperty) error
	Initialized() bool

	WriteEntry(entry *DataStoreEntry) error
	ReadEntry(entryId string) (*DataStoreEntry, error)
	DeleteEntry(entryId string) error

	Type() string
	Location() string
}
