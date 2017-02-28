// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

func GenerateTestConfig() map[string]*ConfigItem {
	configItems := make(map[string]*ConfigItem)

	itemName := "dataStore"
	item := GetConfigItem(itemName)
	propName := "dataStoreType"
	item.Properties[propName] = GetConfigProperty(propName, "InMemoryDataStore", "in memory datastore", false)
	configItems[itemName] = item

	itemName = "keyStore"
	item = GetConfigItem(itemName)
	propName = "keyStoreType"
	item.Properties[propName] = GetConfigProperty(propName, "InMemoryKeyStore", "in memory keystore", false)
	configItems[itemName] = item

	return configItems
}

func GetConfigItem(name string) *ConfigItem {
	return &ConfigItem{
		Name: name,
		Properties: make(map[string]*ConfigProperty),
	}
}

func GetConfigProperty(name, val, desc string, sensitive bool) *ConfigProperty {
	return &ConfigProperty{
		Name: name,
		Value: val,
		Description: desc,
		Sensitive: sensitive,
	}
}