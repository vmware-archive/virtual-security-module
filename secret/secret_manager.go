// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"github.com/vmware/virtual-security-module/config"
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

func (secretManager *SecretManager) Init(configItems map[string]*config.ConfigItem, ds vds.DataStoreAdapter, ks vks.KeyStoreAdapter) error {
	secretManager.dataStore = ds
	secretManager.keyStore = ks

	return nil
}

func (secretManager *SecretManager) Close() error {
	return nil
}

func (secretManager *SecretManager) CreateSecret(secretEntry *model.SecretEntry) (string, error) {
	// verify id doesn't exist, in case client has provided an id
	if secretEntry.Id != "" {
		_, err := secretManager.dataStore.ReadEntry(secretEntry.Id)
		if err == nil {
			return "", util.ErrAlreadyExists
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

	id := secretEntry.Id

	// create new entry id unless one has been provided by the client
	if id == "" {
		id = util.NewUUID()
	}

	se := &model.SecretEntry{
		Id:                     id,
		SecretData:             encryptedSecretData,
		OwnerEntryId:           secretEntry.OwnerEntryId,
		NamespaceEntryId:       secretEntry.NamespaceEntryId,
		ExpirationTime:         secretEntry.ExpirationTime,
		AuthorizationPolicyIds: secretEntry.AuthorizationPolicyIds,
	}

	// create a data store entry and save it
	dataStoreEntry, err := vds.SecretEntryToDataStoreEntry(se)
	if err != nil {
		return "", err
	}
	if err := secretManager.dataStore.WriteEntry(dataStoreEntry); err != nil {
		return "", err
	}

	// persist key using virtual key store
	if err := secretManager.keyStore.Write(id, key); err != nil {
		return "", err
	}

	return id, nil
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
