// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"fmt"

	"github.com/vmware/virtual-security-module/config"
)

func GetDataStoreFromConfig(configItems map[string]*config.ConfigItem) (DataStoreAdapter, error) {
	dsConfigItem, ok := configItems[PropertyNameDataStore]
	if !ok {
		return nil, fmt.Errorf("Mandatory config item %v is missing in config", PropertyNameDataStore)
	}

	dsTypeProperty, ok := dsConfigItem.Properties[PropertyNameDataStoreType]
	if !ok {
		return nil, fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameDataStoreType)
	}

	dsAdapter, err := DataStoreRegistrar.Get(dsTypeProperty.Value)
	if err != nil {
		return nil, err
	}

	if err := dsAdapter.Init(dsConfigItem.Properties); err != nil {
		return nil, err
	}

	return dsAdapter, nil
}
