// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"fmt"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/crypt"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

type SecretManager struct {
	dataStore vds.DataStoreAdapter
	keyStore vks.KeyStoreAdapter
}

func New() *SecretManager {
	return &SecretManager{}
}

func (secretManager *SecretManager) Type() string {
	return "SecretManager"
}

func (secretManager *SecretManager) Init(configItems map[string]*config.ConfigItem) error {
	return secretManager.initFromConfig(configItems)
}

func (secretManager *SecretManager) Close() error {
	return nil
}

func (secretManager *SecretManager) CreateSecret(secretEntry *model.SecretEntry) (string, error) {
	// verify id doesn't exist, in case client has provided an id
	if secretEntry.Id != "" {
		_, err := secretManager.dataStore.ReadEntry(secretEntry.Id)
		if err == nil {
			return "", fmt.Errorf("Id %v already exists", secretEntry.Id)
		}
	}

	// generate encryption key for secret
	key, err := crypt.GenerateKey()
	if err != nil {
		return "", err
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// encrypt secret data using key
	encryptedSecretData, err := crypt.Encrypt(secretEntry.SecretData, key)
	if err != nil {
		return "", err
	}

	// create new entry id unless one has been provided by the client
	if secretEntry.Id == "" {
		secretEntry.Id = util.NewUUID()
	}

	// override secret data with encrypted data
	secretEntry.SecretData = encryptedSecretData

	// create a data store entry and save it
	dataStoreEntry, err := vds.SecretEntryToDataStoreEntry(secretEntry)
	if err != nil {
		return "", err
	}
	if err := secretManager.dataStore.WriteEntry(dataStoreEntry); err != nil {
		return "", err
	}

	// persist key using virtual key store
	if err := secretManager.keyStore.Write(secretEntry.Id, key); err != nil {
		return "", err
	}

	return secretEntry.Id, nil
}

func (secretManager *SecretManager) GetSecret(secretId string) (*model.SecretEntry, error) {
	// fetch data store entry
	dataStoreEntry, err := secretManager.dataStore.ReadEntry(secretId)
	if err != nil {
		return nil, err
	}

	// fetch encryption key
	key, err := secretManager.keyStore.Read(secretId)
	if err != nil {
		return nil, err
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// decrypt secret data using key
	decryptedData, err := crypt.Decrypt(dataStoreEntry.Data, key)
	if err != nil {
		return nil, err
	}

	// transform data store entry to secret entry and set decrypted data
	secretEntry, err := vds.DataStoreEntryToSecretEntry(dataStoreEntry)
	if err != nil {
		return nil, err
	}
	secretEntry.SecretData = decryptedData

	return secretEntry, nil
}

func (secretManager *SecretManager) initFromConfig(configItems map[string]*config.ConfigItem) error {
	if err := secretManager.initDataStoreFromConfig(configItems); err != nil {
		return err
	}
	if err := secretManager.initKeyStoreFromConfig(configItems); err != nil {
		return err
	}

	return nil
}

func (secretManager *SecretManager) initDataStoreFromConfig(configItems map[string]*config.ConfigItem) error {
	dsConfigItem, ok := configItems[vds.PropertyNameDataStore]
	if !ok {
		return fmt.Errorf("Mandatory config item %v is missing in config", vds.PropertyNameDataStore)
	}
	dsTypeProperty, ok := dsConfigItem.Properties[vds.PropertyNameDataStoreType]
	if !ok {
		return fmt.Errorf("Mandatory config property %v is missing in config", vds.PropertyNameDataStoreType)
	}
	dsAdapter, err := vds.DataStoreRegistrar.Get(dsTypeProperty.Value)
	if err != nil {
		return err
	}
	if err := dsAdapter.Init(dsConfigItem.Properties); err != nil {
		return err
	}

	secretManager.dataStore = dsAdapter

	return nil
}

func (secretManager *SecretManager) initKeyStoreFromConfig(configItems map[string]*config.ConfigItem) error {
	ksConfigItem, ok := configItems[vks.PropertyNameKeyStore]
	if !ok {
		return fmt.Errorf("Mandatory config item %v is missing in config", vks.PropertyNameKeyStore)
	}
	ksTypeProperty, ok := ksConfigItem.Properties[vks.PropertyNameKeyStoreType]
	if !ok {
		return fmt.Errorf("Mandatory config property %v is missing in config", vks.PropertyNameKeyStoreType)
	}
	ksAdapter, err := vks.KeyStoreRegistrar.Get(ksTypeProperty.Value)
	if err != nil {
		return err
	}
	if err := ksAdapter.Init(ksConfigItem.Properties); err != nil {
		return err
	}

	secretManager.keyStore = ksAdapter

	return nil
}