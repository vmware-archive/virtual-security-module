// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	gocontext "context"
	"fmt"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/crypt"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

const DataSecretTypeName = "Data"

func init() {
	if err := SecretTypeRegistrar.Register(DataSecretTypeName, NewDataSecretType()); err != nil {
		panic(fmt.Sprintf("Failed to register secret type %v: %v", DataSecretTypeName, err))
	}
}

// A data-only secret type.
// This is the simplest secret type.
type DataSecretType struct {
	dataStore vds.DataStoreAdapter
	keyStore  vks.KeyStoreAdapter
}

func NewDataSecretType() *DataSecretType {
	return &DataSecretType{}
}

func (dataST *DataSecretType) Type() string {
	return DataSecretTypeName
}

func (dataST *DataSecretType) Init(moduleInitContext *context.ModuleInitContext) error {
	dataST.dataStore = moduleInitContext.DataStore
	dataST.keyStore = moduleInitContext.KeyStore

	return nil
}

func (dataST *DataSecretType) CreateSecret(ctx gocontext.Context, secretEntry *model.SecretEntry) (string, error) {
	if len(secretEntry.SecretData) == 0 {
		return "", util.ErrInputValidation
	}

	secretPath := vds.SecretIdToPath(secretEntry.Id)

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
	if err := dataST.dataStore.CreateEntry(dataStoreEntry); err != nil {
		return "", err
	}

	// persist key using virtual key store
	if err := dataST.keyStore.Create(secretPath, key); err != nil {
		return "", err
	}

	return secretEntry.Id, nil
}

func (dataST *DataSecretType) GetSecret(ctx gocontext.Context, secretEntry *model.SecretEntry) (*model.SecretEntry, error) {
	secretPath := vds.SecretIdToPath(secretEntry.Id)

	// fetch encryption key
	key, err := dataST.keyStore.Read(secretPath)
	if err != nil {
		return nil, err
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// decrypt secret data using key
	decryptedData, err := crypt.Decrypt(secretEntry.SecretData, key)
	if err != nil {
		return nil, util.ErrInternal
	}

	// set decrypted data
	secretEntry.SecretData = decryptedData

	return secretEntry, nil
}

func (dataST *DataSecretType) DeleteSecret(ctx gocontext.Context, secretEntry *model.SecretEntry) error {
	secretPath := vds.SecretIdToPath(secretEntry.Id)

	if err := dataST.dataStore.DeleteEntry(secretPath); err != nil {
		return err
	}

	if err := dataST.keyStore.Delete(secretPath); err != nil {
		return err
	}

	return nil
}
