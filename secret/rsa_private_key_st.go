// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	gocontext "context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/crypt"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

const RSAPrivateKeySecretTypeName = "RSAPrivateKey"

func init() {
	if err := SecretTypeRegistrar.Register(RSAPrivateKeySecretTypeName, NewRSAPrivateKeySecretType()); err != nil {
		panic(fmt.Sprintf("Failed to register secret type %v: %v", RSAPrivateKeySecretTypeName, err))
	}
}

type RSAPrivateKeySecretType struct {
	dataStore vds.DataStoreAdapter
	keyStore  vks.KeyStoreAdapter
}

type RSAPrivateKeySecretMetaData struct {
	KeyLength int `json:"keyLength"`
}

func NewRSAPrivateKeySecretType() *RSAPrivateKeySecretType {
	return &RSAPrivateKeySecretType{}
}

func (rsaPrivKeyST *RSAPrivateKeySecretType) Type() string {
	return RSAPrivateKeySecretTypeName
}

func (rsaPrivKeyST *RSAPrivateKeySecretType) Init(moduleInitContext *context.ModuleInitContext) error {
	rsaPrivKeyST.dataStore = moduleInitContext.DataStore
	rsaPrivKeyST.keyStore = moduleInitContext.KeyStore

	return nil
}

func (rsaPrivKeyST *RSAPrivateKeySecretType) CreateSecret(ctx gocontext.Context, secretEntry *model.SecretEntry) (string, error) {
	// get desired key length
	var rsaPrivKeySTMetaData RSAPrivateKeySecretMetaData
	if err := json.Unmarshal([]byte(secretEntry.MetaData), &rsaPrivKeySTMetaData); err != nil {
		return "", util.ErrInputValidation
	}

	keyLength := rsaPrivKeySTMetaData.KeyLength
	if keyLength <= 0 || keyLength > 2048 {
		return "", util.ErrInputValidation
	}

	// we expect the input to contain no data, as we're generating the data
	// (the private key) in this case
	if len(secretEntry.SecretData) > 0 {
		return "", util.ErrInputValidation
	}

	secretPath := vds.SecretIdToPath(secretEntry.Id)

	// verify id doesn't exist
	if _, err := rsaPrivKeyST.dataStore.ReadEntry(secretPath); err == nil {
		return "", util.ErrAlreadyExists
	}

	// generate encryption key for secret
	key, err := crypt.GenerateKey()
	if err != nil {
		return "", util.ErrInternal
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// generate secret data (private key in this case) and encrypt it using temporary key
	pk, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return "", err
	}
	b := x509.MarshalPKCS1PrivateKey(pk)
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: b,
	}
	pkPEM := pem.EncodeToMemory(&block)

	encryptedSecretData, err := crypt.Encrypt(pkPEM, key)
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
	if err := rsaPrivKeyST.dataStore.WriteEntry(dataStoreEntry); err != nil {
		return "", err
	}

	// persist key using virtual key store
	if err := rsaPrivKeyST.keyStore.Write(secretPath, key); err != nil {
		return "", err
	}

	return secretEntry.Id, nil
}

func (rsaPrivKeyST *RSAPrivateKeySecretType) GetSecret(ctx gocontext.Context, secretEntry *model.SecretEntry) (*model.SecretEntry, error) {
	secretPath := vds.SecretIdToPath(secretEntry.Id)

	// fetch encryption key
	key, err := rsaPrivKeyST.keyStore.Read(secretPath)
	if err != nil {
		return nil, err
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// decrypt secret data using key
	pkPEM, err := crypt.Decrypt(secretEntry.SecretData, key)
	if err != nil {
		return nil, util.ErrInternal
	}

	// set decrypted data
	secretEntry.SecretData = pkPEM

	return secretEntry, nil
}

func (rsaPrivKeyST *RSAPrivateKeySecretType) DeleteSecret(ctx gocontext.Context, secretEntry *model.SecretEntry) error {
	secretPath := vds.SecretIdToPath(secretEntry.Id)

	if err := rsaPrivKeyST.dataStore.DeleteEntry(secretPath); err != nil {
		return err
	}

	if err := rsaPrivKeyST.keyStore.Delete(secretPath); err != nil {
		return err
	}

	return nil
}
