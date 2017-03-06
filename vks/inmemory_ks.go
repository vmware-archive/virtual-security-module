// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"fmt"
	"sync"

	"github.com/vmware/virtual-security-module/config"
)

const ksType = "InMemoryKeyStore"

func init() {
	if err := KeyStoreRegistrar.Register(ksType, New()); err != nil {
		panic(fmt.Sprintf("Failed to register key store type %v: %v", ksType, err))
	}
}

// An implementation of a keystore in-memory.
// Useful for testing. Not recommended for production!!
type InMemoryKS struct {
	keyMap map[string][]byte
	mutex sync.Mutex
}

func New() *InMemoryKS {
	return &InMemoryKS {
		keyMap: make(map[string][]byte),
	}
}

func (ks *InMemoryKS) Init(map[string]*config.ConfigProperty) error {
	return nil
}

func (ks *InMemoryKS) CompleteInit(map[string]*config.ConfigProperty) error {
	return nil
}

func (ks *InMemoryKS) Initialized() bool {
	return true
}

func (ks *InMemoryKS) Write(alias string, key []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

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
		return nil, fmt.Errorf("Key with alias %v not found", alias)
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
		return fmt.Errorf("Key with alias %v not found", alias)
	}

	delete(ks.keyMap, alias)

	return nil
}

func (ks *InMemoryKS) Type() string {
	return ksType
}

func (ks *InMemoryKS) Location() string {
	return ""
}
