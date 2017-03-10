// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"fmt"
	
	"github.com/vmware/virtual-security-module/config"
)

func GetKeyStoreFromConfig(configItems map[string]*config.ConfigItem) (KeyStoreAdapter, error) {
	ksConfigItem, ok := configItems[PropertyNameKeyStore]
	if !ok {
		return nil, fmt.Errorf("Mandatory config item %v is missing in config", PropertyNameKeyStore)
	}
	
	ksTypeProperty, ok := ksConfigItem.Properties[PropertyNameKeyStoreType]
	if !ok {
		return nil, fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameKeyStoreType)
	}
	
	ksAdapter, err := KeyStoreRegistrar.Get(ksTypeProperty.Value)
	if err != nil {
		return nil, err
	}
	
	if err := ksAdapter.Init(ksConfigItem.Properties); err != nil {
		return nil, err
	}

	return ksAdapter, nil
}