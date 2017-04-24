// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"fmt"
	"os"
	"testing"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

var sm *SecretManager

func TestMain(m *testing.M) {
	cfg := config.GenerateTestConfig()

	ds, err := vds.GetDataStoreFromConfig(cfg)
	if err != nil {
		fmt.Printf("Failed to get data store from config: %v\n", err)
		os.Exit(1)
	}

	ks, err := vks.GetKeyStoreFromConfig(cfg)
	if err != nil {
		fmt.Printf("Failed to get key store from config: %v\n", err)
		os.Exit(1)
	}

	sm = New()
	az := context.GetTestAuthzManager()
	if err := sm.Init(context.NewModuleInitContext(cfg, ds, ks, az)); err != nil {
		fmt.Printf("Failed to initialize secret manager: %v\n", err)
		os.Exit(1)
	}
	defer sm.Close()

	apiTestSetup()
	defer apiTestCleanup()

	os.Exit(m.Run())
}
