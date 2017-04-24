// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	gocontext "context"
	"path"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

type SecretManager struct {
	dataStore    vds.DataStoreAdapter
	keyStore     vks.KeyStoreAdapter
	authzManager context.AuthorizationManager
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
	secretManager.authzManager = moduleInitContext.AuthzManager

	if err := SecretTypeRegistrar.InitSecretTypes(moduleInitContext); err != nil {
		return err
	}

	return nil
}

func (secretManager *SecretManager) Close() error {
	return nil
}

func (secretManager *SecretManager) CreateSecret(ctx gocontext.Context, secretEntry *model.SecretEntry) (string, error) {
	secretPath := vds.SecretIdToPath(secretEntry.Id)

	if err := secretManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpCreate}, path.Dir(secretPath)); err != nil {
		return "", err
	}

	secretType, err := SecretTypeRegistrar.Get(secretEntry.Type)
	if err != nil {
		return "", util.ErrInputValidation
	}

	return secretType.CreateSecret(ctx, secretEntry)
}

func (secretManager *SecretManager) GetSecret(ctx gocontext.Context, secretId string) (*model.SecretEntry, error) {
	secretPath := vds.SecretIdToPath(secretId)

	if err := secretManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpRead}, path.Dir(secretPath)); err != nil {
		return nil, err
	}

	secretEntry, err := secretManager.getSecretEntry(secretPath)
	if err != nil {
		return nil, err
	}

	secretType, err := SecretTypeRegistrar.Get(secretEntry.Type)
	if err != nil {
		return nil, util.ErrInternal
	}

	return secretType.GetSecret(ctx, secretEntry)
}

func (secretManager *SecretManager) DeleteSecret(ctx gocontext.Context, secretId string) error {
	secretPath := vds.SecretIdToPath(secretId)

	if err := secretManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpDelete}, path.Dir(secretPath)); err != nil {
		return err
	}

	secretEntry, err := secretManager.getSecretEntry(secretPath)
	if err != nil {
		return err
	}

	secretType, err := SecretTypeRegistrar.Get(secretEntry.Type)
	if err != nil {
		return util.ErrInternal
	}

	return secretType.DeleteSecret(ctx, secretEntry)
}

func (secretManager *SecretManager) getSecretEntry(secretPath string) (*model.SecretEntry, error) {
	dataStoreEntry, err := secretManager.dataStore.ReadEntry(secretPath)
	if err != nil {
		return nil, err
	}

	secretEntry, err := vds.DataStoreEntryToSecretEntry(dataStoreEntry)
	if err != nil {
		return nil, err
	}

	return secretEntry, nil
}
