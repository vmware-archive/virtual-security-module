// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"github.com/vmware/virtual-security-module/config"
)

const (
	PropertyNameKeyStore            = "keyStore"
	PropertyNameKeyStoreType        = "keyStoreType"
	PropertyNameKeyStoreLocation    = "keyStoreLocation"
	PropertyNameKeyStoreCredentials = "keyStoreCredentials"
	PropertyNameOutOfBandInit       = "keyStoreOutOfBandInit"
)

type KeyStoreAdapter interface {
	Init(map[string]*config.ConfigProperty) error
	CompleteInit(map[string]*config.ConfigProperty) error
	Initialized() bool

	Write(alias string, key []byte) error
	Read(alias string) ([]byte, error)
	Delete(alias string) error

	Type() string
	Location() string
}
