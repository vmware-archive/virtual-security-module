// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authz

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

var az *AuthzManager

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

	az = New()
	if err := az.Init(context.NewModuleInitContext(cfg, ds, ks)); err != nil {
		fmt.Printf("Failed to initialize authz manager: %v\n", err)
		os.Exit(1)
	}

	apiTestSetup()
	defer apiTestCleanup()

	os.Exit(m.Run())
}

func TestCreateAndGetPolicy(t *testing.T) {
	pe := &model.AuthorizationPolicyEntry{
		Id:                "id1",
		RoleLabels:        []string{"admin"},
		AllowedOperations: []model.Operation{model.Operation{Label: model.OpCreate}},
		Owner:             "user0",
	}

	id, err := az.CreatePolicy(pe)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}
	if len(id) == 0 {
		t.Fatalf("Failed to create policy: returned id is empty")
	}

	pe2, err := az.GetPolicy(id)
	if err != nil {
		t.Fatalf("Failed to get policy for id %v: %v", id, err)
	}

	if !reflect.DeepEqual(pe, pe2) {
		t.Fatalf("Created and retrieved policies do not match: %v %v", pe, pe2)
	}

	if err := az.DeletePolicy(id); err != nil {
		t.Fatalf("Failed to delete secret for id %v: %v", id, err)
	}
}
