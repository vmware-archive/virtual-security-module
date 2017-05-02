// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"fmt"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/crypt"
)

const (
	secretSharerBits = 2048
)

func GetVirtualKeyStoreFromConfig(cfg *config.Config) (*VirtualKeyStore, error) {
	vks := NewVirtualKeyStore()

	if cfg.VirtualKeyStoreConfig.KeyStoreCount <= 0 {
		return nil, fmt.Errorf("invalid keyStoreCount: %v", cfg.VirtualKeyStoreConfig.KeyStoreCount)
	}
	vks.keyStoreCount = cfg.VirtualKeyStoreConfig.KeyStoreCount

	if cfg.VirtualKeyStoreConfig.KeyStoreThreshold < 1 || cfg.VirtualKeyStoreConfig.KeyStoreThreshold > cfg.VirtualKeyStoreConfig.KeyStoreCount {
		return nil, fmt.Errorf("invalid KeyStoreThreshold: %v", cfg.VirtualKeyStoreConfig.KeyStoreThreshold)
	}
	vks.keyStoreThreshold = cfg.VirtualKeyStoreConfig.KeyStoreThreshold

	keyStores, err := getKeyStoresFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	if len(keyStores) != vks.keyStoreCount {
		return nil, fmt.Errorf("Number of configured key stores %v is different than expected: %v", len(keyStores), vks.keyStoreCount)
	}

	vks.keyStores = keyStores
	vks.secretSharer = crypt.NewSecretSharerRandField(secretSharerBits, vks.keyStoreCount, vks.keyStoreThreshold)
	vks.initialized = true

	return vks, nil
}

func getKeyStoresFromConfig(cfg *config.Config) ([]KeyStoreAdapter, error) {
	ksAdapters := make([]KeyStoreAdapter, 0, cfg.VirtualKeyStoreConfig.KeyStoreCount)

	for _, ksConfig := range cfg.VirtualKeyStoreConfig.KeyStores {
		ksAdapter, err := KeyStoreRegistrar.Get(ksConfig.StoreType)
		if err != nil {
			return []KeyStoreAdapter{}, err
		}

		if err := ksAdapter.Init(&ksConfig); err != nil {
			return []KeyStoreAdapter{}, err
		}

		ksAdapters = append(ksAdapters, ksAdapter)
	}

	return ksAdapters, nil
}
