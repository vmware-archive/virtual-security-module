// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authz

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

var az *AuthzManager
var ds vds.DataStoreAdapter

func TestMain(m *testing.M) {
	cfg := config.GenerateTestConfig()

	var err error
	ds, err = vds.GetDataStoreFromConfig(cfg)
	if err != nil {
		fmt.Printf("Failed to get data store from config: %v\n", err)
		os.Exit(1)
	}

	vKeyStore, err := vks.GetVirtualKeyStoreFromConfig(cfg)
	if err != nil {
		fmt.Printf("Failed to get key store from config: %v\n", err)
		os.Exit(1)
	}

	az = New()
	if err := az.Init(context.NewModuleInitContext(cfg, ds, vKeyStore, context.GetTestAuthzManager())); err != nil {
		fmt.Printf("Failed to initialize authz manager: %v\n", err)
		os.Exit(1)
	}

	apiTestSetup()
	defer apiTestCleanup()

	os.Exit(m.Run())
}

func TestCreateAndGetPolicyInRootNamespace(t *testing.T) {
	namespaceId := "/"
	if err := createNamespace(namespaceId, "root", []string{}); err != nil {
		t.Fatalf("Failed to create namespace %v: %v", namespaceId, err)
	}

	policyId := "id1"

	pe, err := createPolicy(policyId, []string{"admin"}, []string{model.OpCreate}, "user0")
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	pe2, err := getPolicy(policyId)
	if err != nil {
		t.Fatalf("Failed to get policy for id %v: %v", policyId, err)
	}

	if !reflect.DeepEqual(pe, pe2) {
		t.Fatalf("Created and retrieved policies do not match: %v %v", pe, pe2)
	}

	if err := deletePolicy(policyId); err != nil {
		t.Fatalf("Failed to delete secret for id %v: %v", policyId, err)
	}

	if err := deleteNamespace(namespaceId); err != nil {
		t.Fatalf("Failed to delete namespace %v: %v", namespaceId, err)
	}
}

func TestCreateAndGetPolicyInNamespace(t *testing.T) {
	namespaceId := "/ns1"
	if err := createNamespace(namespaceId, "root", []string{}); err != nil {
		t.Fatalf("Failed to create namespace %v: %v", namespaceId, err)
	}

	policyId := path.Join(strings.TrimPrefix(namespaceId, "/"), "id1")

	pe, err := createPolicy(policyId, []string{"admin"}, []string{model.OpCreate}, "user0")
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	pe2, err := getPolicy(policyId)
	if err != nil {
		t.Fatalf("Failed to get policy for id %v: %v", policyId, err)
	}

	if !reflect.DeepEqual(pe, pe2) {
		t.Fatalf("Created and retrieved policies do not match: %v %v", pe, pe2)
	}

	if err := deletePolicy(policyId); err != nil {
		t.Fatalf("Failed to delete secret for id %v: %v", policyId, err)
	}

	if err := deleteNamespace(namespaceId); err != nil {
		t.Fatalf("Failed to delete namespace %v: %v", namespaceId, err)
	}
}

func createPolicy(policyId string, roleLabels []string, allowedOps []string, owner string) (*model.AuthorizationPolicyEntry, error) {
	allowedOperations := make([]model.Operation, 0, len(allowedOps))
	for _, allowedOp := range allowedOps {
		allowedOperations = append(allowedOperations, model.Operation{Label: allowedOp})
	}

	pe := &model.AuthorizationPolicyEntry{
		Id:                policyId,
		RoleLabels:        roleLabels,
		AllowedOperations: allowedOperations,
		Owner:             owner,
	}

	id, err := az.CreatePolicy(context.GetTestRequestContext(), pe)
	if err != nil {
		return nil, err
	}

	if len(id) == 0 {
		return nil, fmt.Errorf("Failed to create policy: returned id is empty")
	}

	if id != policyId {
		return nil, fmt.Errorf("created and retrieved policy is are different: %v %v", policyId, id)
	}

	return pe, nil
}

func getPolicy(policyId string) (*model.AuthorizationPolicyEntry, error) {
	return az.GetPolicy(context.GetTestRequestContext(), policyId)
}

func deletePolicy(policyId string) error {
	return az.DeletePolicy(context.GetTestRequestContext(), policyId)
}

func createNamespace(namespacePath, owner string, roleLabels []string) error {
	ne := &model.NamespaceEntry{
		Path:       namespacePath,
		Owner:      owner,
		RoleLabels: roleLabels,
	}

	dsEntry, err := vds.NamespaceEntryToDataStoreEntry(ne)
	if err != nil {
		return err
	}

	if err := ds.CreateEntry(dsEntry); err != nil {
		return err
	}

	return nil
}

func deleteNamespace(namespacePath string) error {
	return ds.DeleteEntry(namespacePath)
}
