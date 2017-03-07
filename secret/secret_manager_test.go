// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/model"
)

var sm *SecretManager

func TestMain(m *testing.M) {
	cfg := config.GenerateTestConfig()

	sm = New()
	if err := sm.Init(cfg); err != nil {
		fmt.Printf("Failed to initialize secret manager: %v\n", err)
		os.Exit(1)
	}
	defer sm.Close()

	apiTestSetup()
	defer apiTestCleanup()
	
	os.Exit(m.Run())
}

func TestCreateAndGetSecretProvidedId(t *testing.T) {
	testCreateAndGetSecret(t, "id1")
}

func TestCreateAndGetSecret(t *testing.T) {
	testCreateAndGetSecret(t, "")
}

func testCreateAndGetSecret(t *testing.T, id string) {
	duration, err := time.ParseDuration("1h")
	if err != nil {
		t.Fatalf("failed to parse duration: %v", err)
	}
	expirationTime := time.Now().Add(duration)

	se := &model.SecretEntry{
		Id: id,
		SecretData: []byte("secret0"),
		OwnerEntryId: "user0",
		NamespaceEntryId: "root",
		ExpirationTime: expirationTime,
		AuthorizationPolicyIds: []string{},
	}

	id2, err := sm.CreateSecret(se)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	if len(id2) == 0 {
		t.Fatalf("Failed to create secret: returned id is empty")
	}

	se2, err := sm.GetSecret(id2)
	if err != nil {
		t.Fatalf("Failed to get secret for id %v: %v", id2, err)
	}
	
	if id == "" {
		se.Id = id2
	}
	if !reflect.DeepEqual(se, se2) {
		t.Fatalf("Created and retrieved secrets are different: %v %v", se, se2)
	}
}