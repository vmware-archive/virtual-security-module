// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"github.com/vmware/virtual-security-module/util"
)

// singleton registrar for data store types
var DataStoreRegistrar *dataStoreRegistrar = newRegistrar()

type dataStoreRegistrar struct {
	dataStores map[string]DataStoreAdapter
}

func newRegistrar() *dataStoreRegistrar {
	return &dataStoreRegistrar{
		dataStores: make(map[string]DataStoreAdapter),
	}
}

func (dsRegistrar *dataStoreRegistrar) Register(dsType string, dsAdapter DataStoreAdapter) error {
	_, ok := dsRegistrar.dataStores[dsType]
	if ok {
		return util.ErrAlreadyExists
	}

	dsRegistrar.dataStores[dsType] = dsAdapter

	return nil
}

func (dsRegistrar *dataStoreRegistrar) Unregister(dsType string) error {
	_, ok := dsRegistrar.dataStores[dsType]
	if !ok {
		return util.ErrNotFound
	}

	delete(dsRegistrar.dataStores, dsType)

	return nil
}

func (dsRegistrar *dataStoreRegistrar) Registered(dsType string) bool {
	_, ok := dsRegistrar.dataStores[dsType]

	return ok
}

func (dsRegistrar *dataStoreRegistrar) Get(dsType string) (DataStoreAdapter, error) {
	dsAdapter, ok := dsRegistrar.dataStores[dsType]

	if !ok {
		return nil, util.ErrNotFound
	}

	return dsAdapter, nil
}
