// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

func GenerateTestConfig() map[string]*ConfigItem {
	configItems := make(map[string]*ConfigItem)

	// data store
	itemName := "dataStore"
	item := GetConfigItem(itemName)
	propName := "dataStoreType"
	item.Properties[propName] = GetConfigProperty(propName, "InMemoryDataStore", "in memory datastore", false)
	configItems[itemName] = item

	// key store
	itemName = "keyStore"
	item = GetConfigItem(itemName)
	propName = "keyStoreType"
	item.Properties[propName] = GetConfigProperty(propName, "InMemoryKeyStore", "in memory keystore", false)
	configItems[itemName] = item
	
	// server
	itemName = "server"
	item = GetConfigItem(itemName)
	
	propName = "http"
	item.Properties[propName] = GetConfigProperty(propName, "true", "enable http", false)
	
	propName = "httpPort"
	item.Properties[propName] = GetConfigProperty(propName, "8090", "http port", false)
	
	propName = "rootInitPubKey"
	item.Properties[propName] = GetConfigProperty(propName, "../certs/test-root-init-public.pem",
		"public key file of the root user during intialization of a new server", false)
	
	propName = "rootInitPriKey"
	item.Properties[propName] = GetConfigProperty(propName, "../certs/test-root-init-private.pem",
		"*** for testing only: private key file of the root user during intialization of a new server ***", false)
	
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