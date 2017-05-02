// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"fmt"
	"sync"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/util"
)

const inMemoryKSType = "InMemoryKeyStore"

func init() {
	if err := KeyStoreRegistrar.Register(inMemoryKSType, NewInMemoryKS()); err != nil {
		panic(fmt.Sprintf("Failed to register key store type %v: %v", inMemoryKSType, err))
	}
}

// An implementation of a keystore in-memory.
// Useful for testing. Not recommended for production!!
type InMemoryKS struct {
	keyMap   map[string][]byte
	mutex    sync.Mutex
	location string
}

func NewInMemoryKS() *InMemoryKS {
	return &InMemoryKS{
		keyMap: make(map[string][]byte),
	}
}

func (ks *InMemoryKS) Init(cfg *config.KeyStoreConfig) error {
	ks.location = cfg.ConnectionString

	return nil
}

func (ks *InMemoryKS) CompleteInit(*config.KeyStoreConfig) error {
	return nil
}

func (ks *InMemoryKS) NewInstance() KeyStoreAdapter {
	return NewInMemoryKS()
}

func (ks *InMemoryKS) Initialized() bool {
	return true
}

func (ks *InMemoryKS) Create(alias string, key []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	_, ok := ks.keyMap[alias]
	if ok {
		return util.ErrAlreadyExists
	}

	buf := make([]byte, len(key))
	copy(buf, key)
	ks.keyMap[alias] = buf

	return nil
}

func (ks *InMemoryKS) Read(alias string) ([]byte, error) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	key, ok := ks.keyMap[alias]
	if !ok {
		return nil, util.ErrNotFound
	}

	buf := make([]byte, len(key))
	copy(buf, key)

	return buf, nil
}

func (ks *InMemoryKS) Delete(alias string) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	_, ok := ks.keyMap[alias]
	if !ok {
		return util.ErrNotFound
	}

	delete(ks.keyMap, alias)

	return nil
}

func (ks *InMemoryKS) Type() string {
	return inMemoryKSType
}

func (ks *InMemoryKS) Location() string {
	return ks.location
}
