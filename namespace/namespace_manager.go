// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package namespace

import (
	"fmt"
	"path"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

type NamespaceManager struct {
	dataStore vds.DataStoreAdapter
	keyStore  vks.KeyStoreAdapter
}

func New() *NamespaceManager {
	return &NamespaceManager{}
}

func (namespaceManager *NamespaceManager) Type() string {
	return "NamespaceManager"
}

func (namespaceManager *NamespaceManager) Init(configuration *config.Config, ds vds.DataStoreAdapter, ks vks.KeyStoreAdapter) error {
	namespaceManager.dataStore = ds
	namespaceManager.keyStore = ks

	if err := namespaceManager.initNamespaces(); err != nil {
		return err
	}

	return nil
}

func (namespaceManager *NamespaceManager) Close() error {
	return nil
}

func (namespaceManager *NamespaceManager) CreateNamespace(namespaceEntry *model.NamespaceEntry) (string, error) {
	_, err := namespaceManager.dataStore.ReadEntry(namespaceEntry.Path)
	if err == nil {
		return "", util.ErrAlreadyExists
	}

	if namespaceEntry.Path != "/" {
		// verify parent path exists
		if _, err := namespaceManager.dataStore.ReadEntry(path.Dir(namespaceEntry.Path)); err != nil {
			return "", util.ErrInputValidation
		}
	}

	dataStoreEntry, err := vds.NamespaceEntryToDataStoreEntry(namespaceEntry)
	if err != nil {
		return "", err
	}
	if err := namespaceManager.dataStore.WriteEntry(dataStoreEntry); err != nil {
		return "", err
	}

	return namespaceEntry.Path, nil
}

func (namespaceManager *NamespaceManager) GetNamespace(path string) (*model.NamespaceEntry, error) {
	dataStoreEntry, err := namespaceManager.dataStore.ReadEntry(path)
	if err != nil {
		return nil, err
	}

	namespaceEntry, err := vds.DataStoreEntryToNamespaceEntry(dataStoreEntry)
	if err != nil {
		return nil, err
	}

	childSearchPattern := util.GetChildSearchPattern(path)
	childEntries, err := namespaceManager.dataStore.SearchEntries(childSearchPattern)
	if err != nil {
		return nil, err
	}
	namespaceEntry.ChildPaths = vds.DataStoreEntriesToPaths(childEntries)

	return namespaceEntry, nil
}

func (namespaceManager *NamespaceManager) DeleteNamespace(path string) error {
	childSearchPattern := util.GetChildSearchPattern(path)
	childNamespaces, err := namespaceManager.dataStore.SearchEntries(childSearchPattern)
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
	if _, err := namespaceManager.GetNamespace(path); err == nil {
		return nil
	}

	namespaceEntry := &model.NamespaceEntry{
		Path: path,
	}

	if _, err := namespaceManager.CreateNamespace(namespaceEntry); err != nil {
		return err
	}

	return nil
}
