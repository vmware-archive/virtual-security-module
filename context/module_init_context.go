// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package context

import (
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

type ModuleInitContext struct {
	Config       *config.Config
	DataStore    vds.DataStoreAdapter
	KeyStore     vks.KeyStoreAdapter
	AuthzManager AuthorizationManager
}

func NewModuleInitContext(config *config.Config, dsAdapter vds.DataStoreAdapter, ksAdapter vks.KeyStoreAdapter, authzManager AuthorizationManager) *ModuleInitContext {
	return &ModuleInitContext{
		Config:       config,
		DataStore:    dsAdapter,
		KeyStore:     ksAdapter,
		AuthzManager: authzManager,
	}
}
