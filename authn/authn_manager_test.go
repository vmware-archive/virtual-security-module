// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"fmt"
	"testing"
	"os"
	
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

var am *AuthnManager

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
	
	am = New()
	if err := am.Init(nil, ds, ks); err != nil {
		fmt.Printf("Failed to initialize authn manager: %v\n", err)
		os.Exit(1)
	}

	builtinProviderTestSetup()
	defer builtinProviderTestCleanup()
	
	apiTestSetup()
	defer apiTestCleanup()
	
	os.Exit(m.Run())
}