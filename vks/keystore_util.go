// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"fmt"
	"github.com/vmware/virtual-security-module/config"
)

func GetKeyStoreFromConfig(configuration *config.Config) (KeyStoreAdapter, error) {
	ksConfigItem := configuration.KeyStoreConfig
	if ksConfigItem == (config.KeyStoreConfig{}) {
		return nil, fmt.Errorf("Mandatory config item %v is missing in config", PropertyNameKeyStore)
	}

	ksTypeProperty := ksConfigItem.StoreType
	if ksTypeProperty == "" {
		return nil, fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameKeyStoreType)
	}

	ksAdapter, err := KeyStoreRegistrar.Get(ksTypeProperty)
	if err != nil {
		return nil, err
	}

	if err := ksAdapter.Init(configuration); err != nil {
		return nil, err
	}

	return ksAdapter, nil
}
