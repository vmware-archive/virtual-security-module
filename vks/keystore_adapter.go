// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"github.com/vmware/virtual-security-module/config"
)

const (
	PropertyNameKeyStore     = "keyStore"
	PropertyNameKeyStoreType = "type"
)

type KeyStoreAdapter interface {
	Init(storeConfig *config.KeyStoreConfig) error
	CompleteInit(*config.KeyStoreConfig) error
	NewInstance() KeyStoreAdapter
	Initialized() bool

	Create(alias string, key []byte) error
	Read(alias string) ([]byte, error)
	Delete(alias string) error

	Type() string
	Location() string
}
