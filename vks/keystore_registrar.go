// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"github.com/vmware/virtual-security-module/util"
)

// singleton registrar for key store types
var KeyStoreRegistrar *keyStoreRegistrar = newRegistrar()

type keyStoreRegistrar struct {
	keyStores map[string]KeyStoreAdapter
}

func newRegistrar() *keyStoreRegistrar {
	return &keyStoreRegistrar{
		keyStores: make(map[string]KeyStoreAdapter),
	}
}

func (ksRegistrar *keyStoreRegistrar) Register(ksType string, ksAdapter KeyStoreAdapter) error {
	_, ok := ksRegistrar.keyStores[ksType]
	if ok {
		return util.ErrAlreadyExists
	}

	ksRegistrar.keyStores[ksType] = ksAdapter

	return nil
}

func (ksRegistrar *keyStoreRegistrar) Unregister(ksType string) error {
	_, ok := ksRegistrar.keyStores[ksType]
	if !ok {
		return util.ErrNotFound
	}

	delete(ksRegistrar.keyStores, ksType)

	return nil
}

func (ksRegistrar *keyStoreRegistrar) Registered(ksType string) bool {
	_, ok := ksRegistrar.keyStores[ksType]

	return ok
}

func (ksRegistrar *keyStoreRegistrar) Get(ksType string) (KeyStoreAdapter, error) {
	ksAdapter, ok := ksRegistrar.keyStores[ksType]

	if !ok {
		return nil, util.ErrNotFound
	}

	return ksAdapter, nil
}
