// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package namespace

import (
	gocontext "context"
	"fmt"
	"path"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

type NamespaceManager struct {
	dataStore    vds.DataStoreAdapter
	keyStore     vks.KeyStoreAdapter
	authzManager context.AuthorizationManager
}

func New() *NamespaceManager {
	return &NamespaceManager{}
}

func (namespaceManager *NamespaceManager) Type() string {
	return "NamespaceManager"
}

func (namespaceManager *NamespaceManager) Init(moduleInitContext *context.ModuleInitContext) error {
	namespaceManager.dataStore = moduleInitContext.DataStore
	namespaceManager.keyStore = moduleInitContext.KeyStore
	namespaceManager.authzManager = moduleInitContext.AuthzManager

	if err := namespaceManager.initNamespaces(); err != nil {
		return err
	}

	return nil
}

func (namespaceManager *NamespaceManager) Close() error {
	return nil
}

func (namespaceManager *NamespaceManager) CreateNamespace(ctx gocontext.Context, namespaceEntry *model.NamespaceEntry) (string, error) {
	if namespaceEntry.Path != "/" {
		if err := namespaceManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpCreate}, path.Dir(namespaceEntry.Path)); err != nil {
			return "", err
		}
	}

	_, err := namespaceManager.dataStore.ReadEntry(namespaceEntry.Path)
	if err == nil {
		return "", util.ErrAlreadyExists
	}

	dataStoreEntry, err := vds.NamespaceEntryToDataStoreEntry(namespaceEntry)
	if err != nil {
		return "", err
	}
	if err := namespaceManager.dataStore.CreateEntry(dataStoreEntry); err != nil {
		return "", err
	}

	return namespaceEntry.Path, nil
}

func (namespaceManager *NamespaceManager) GetNamespace(ctx gocontext.Context, path string) (*model.NamespaceEntry, error) {
	if err := namespaceManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpRead}, path); err != nil {
		return nil, err
	}

	dataStoreEntry, err := namespaceManager.dataStore.ReadEntry(path)
	if err != nil {
		return nil, err
	}

	namespaceEntry, err := vds.DataStoreEntryToNamespaceEntry(dataStoreEntry)
	if err != nil {
		return nil, err
	}

	childEntries, err := namespaceManager.dataStore.SearchChildEntries(path)
	if err != nil {
		return nil, err
	}
	namespaceEntry.ChildPaths = vds.DataStoreEntriesToPaths(childEntries)

	return namespaceEntry, nil
}

func (namespaceManager *NamespaceManager) DeleteNamespace(ctx gocontext.Context, path string) error {
	if err := namespaceManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpDelete}, path); err != nil {
		return err
	}

	dsEntry, err := namespaceManager.dataStore.ReadEntry(path)
	if err != nil {
		return err
	}

	if !vds.IsNamespaceEntry(dsEntry) {
		return util.ErrInputValidation
	}

	childNamespaces, err := namespaceManager.dataStore.SearchChildEntries(path)
	if err != nil {
		return err
	}

	if len(childNamespaces) != 0 {
		return fmt.Errorf("Namespace %v has child namespaces", path)
	}

	if err := namespaceManager.dataStore.DeleteEntry(path); err != nil {
		return err
	}

	return nil
}

func (namespaceManager *NamespaceManager) initNamespaces() error {
	paths := []string{"/", "/users", "/secrets"}

	for _, path := range paths {
		if err := namespaceManager.createNamespaceIfNotExists(path); err != nil {
			return err
		}
	}

	return nil
}

func (namespaceManager *NamespaceManager) createNamespaceIfNotExists(path string) error {
	systemContext := context.GetSystemRequestContext()
	if _, err := namespaceManager.GetNamespace(systemContext, path); err == nil {
		return nil
	}

	namespaceEntry := &model.NamespaceEntry{
		Path:  path,
		Owner: "root",
	}

	if _, err := namespaceManager.CreateNamespace(systemContext, namespaceEntry); err != nil {
		return err
	}

	return nil
}
