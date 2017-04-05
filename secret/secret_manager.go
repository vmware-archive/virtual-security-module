// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"path"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/crypt"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

type SecretManager struct {
	dataStore vds.DataStoreAdapter
	keyStore  vks.KeyStoreAdapter
}

func New() *SecretManager {
	return &SecretManager{}
}

func (secretManager *SecretManager) Type() string {
	return "SecretManager"
}

func (secretManager *SecretManager) Init(moduleInitContext *context.ModuleInitContext) error {
	secretManager.dataStore = moduleInitContext.DataStore
	secretManager.keyStore = moduleInitContext.KeyStore

	return nil
}

func (secretManager *SecretManager) Close() error {
	return nil
}

func (secretManager *SecretManager) CreateSecret(secretEntry *model.SecretEntry) (string, error) {
	secretPath := vds.SecretIdToPath(secretEntry.Id)

	// verify id doesn't exist
	if _, err := secretManager.dataStore.ReadEntry(secretPath); err == nil {
		return "", util.ErrAlreadyExists
	}

	// verify parent path exists and it's a namespace
	parentPath := path.Dir(secretPath)
	if parentPath != "/secrets" {
		dsEntry, err := secretManager.dataStore.ReadEntry(parentPath)
		if err != nil {
			return "", util.ErrInputValidation
		}

		if !vds.IsNamespaceEntry(dsEntry) {
			return "", util.ErrInputValidation
		}
	}

	// generate encryption key for secret
	key, err := crypt.GenerateKey()
	if err != nil {
		return "", util.ErrInternal
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// encrypt secret data using key
	encryptedSecretData, err := crypt.Encrypt(secretEntry.SecretData, key)
	if err != nil {
		return "", util.ErrInternal
	}

	se := model.NewSecretEntry(secretEntry)
	se.SecretData = encryptedSecretData

	// create a data store entry and save it
	dataStoreEntry, err := vds.SecretEntryToDataStoreEntry(se)
	if err != nil {
		return "", err
	}
	if err := secretManager.dataStore.WriteEntry(dataStoreEntry); err != nil {
		return "", err
	}

	// persist key using virtual key store
	if err := secretManager.keyStore.Write(secretPath, key); err != nil {
		return "", err
	}

	return secretEntry.Id, nil
}

func (secretManager *SecretManager) GetSecret(secretId string) (*model.SecretEntry, error) {
	secretPath := vds.SecretIdToPath(secretId)

	// fetch data store entry
	dataStoreEntry, err := secretManager.dataStore.ReadEntry(secretPath)
	if err != nil {
		return nil, err
	}

	// fetch encryption key
	key, err := secretManager.keyStore.Read(secretPath)
	if err != nil {
		return nil, err
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// decrypt secret data using key
	decryptedData, err := crypt.Decrypt(dataStoreEntry.Data, key)
	if err != nil {
		return nil, util.ErrInternal
	}

	// transform data store entry to secret entry and set decrypted data
	secretEntry, err := vds.DataStoreEntryToSecretEntry(dataStoreEntry)
	if err != nil {
		return nil, err
	}
	secretEntry.SecretData = decryptedData

	return secretEntry, nil
}

func (secretManager *SecretManager) DeleteSecret(secretId string) error {
	secretPath := vds.SecretIdToPath(secretId)

	dsEntry, err := secretManager.dataStore.ReadEntry(secretPath)
	if err != nil {
		return err
	}

	if !vds.IsSecretEntry(dsEntry) {
		return util.ErrInputValidation
	}

	if err := secretManager.dataStore.DeleteEntry(secretPath); err != nil {
		return err
	}

	if err := secretManager.keyStore.Delete(secretPath); err != nil {
		return err
	}

	return nil
}
