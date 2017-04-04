// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"encoding/json"
	"fmt"

	"github.com/vmware/virtual-security-module/config"
)

func GetDataStoreFromConfig(configuration *config.Config) (DataStoreAdapter, error) {
	dsConfigItem := configuration.DataStoreConfig
	if dsConfigItem == (config.DataStoreConfig{}) {
		return nil, fmt.Errorf("Mandatory config item %v is missing in config", PropertyNameDataStore)
	}

	dsTypeProperty := dsConfigItem.StoreType
	if dsTypeProperty == "" {
		return nil, fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameDataStoreType)
	}

	dsAdapter, err := DataStoreRegistrar.Get(dsTypeProperty)
	if err != nil {
		return nil, err
	}

	if err := dsAdapter.Init(configuration); err != nil {
		return nil, err
	}

	return dsAdapter, nil
}

func IsSecretEntry(dsEntry *DataStoreEntry) bool {
	var metaData MetaData
	if err := json.Unmarshal([]byte(dsEntry.MetaData), &metaData); err != nil {
		return false
	}

	return metaData.Type == secretEntryType
}

func IsUserEntry(dsEntry *DataStoreEntry) bool {
	var metaData MetaData
	if err := json.Unmarshal([]byte(dsEntry.MetaData), &metaData); err != nil {
		return false
	}

	return metaData.Type == userEntryType
}

func IsNamespaceEntry(dsEntry *DataStoreEntry) bool {
	var metaData MetaData
	if err := json.Unmarshal([]byte(dsEntry.MetaData), &metaData); err != nil {
		return false
	}

	return metaData.Type == namespaceEntryType
}

func IsAuthorizationPolicyEntry(dsEntry *DataStoreEntry) bool {
	var metaData MetaData
	if err := json.Unmarshal([]byte(dsEntry.MetaData), &metaData); err != nil {
		return false
	}

	return metaData.Type == authorizationPolicyEntryType
}
