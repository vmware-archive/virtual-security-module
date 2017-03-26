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
		_, err = namespaceManager.dataStore.ReadEntry(path.Dir(namespaceEntry.Path))
		if err != nil {
			// parent path does not exist
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
