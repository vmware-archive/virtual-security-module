// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"testing"
	"time"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
)

func TestCreateAndGetDataSecret(t *testing.T) {
	se := &model.SecretEntry{
		Id:             "id1",
		Type:           DataSecretTypeName,
		MetaData:       "",
		SecretData:     []byte("secret0"),
		Owner:          "user0",
		ExpirationTime: time.Now().Add(time.Hour),
	}

	id2, err := sm.CreateSecret(context.GetTestRequestContext(), se)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	if len(id2) == 0 {
		t.Fatalf("Failed to create secret: returned id is empty")
	}

	se2, err := sm.GetSecret(context.GetTestRequestContext(), id2)
	if err != nil {
		t.Fatalf("Failed to get secret for id %v: %v", id2, err)
	}

	if ok := model.SecretsEqual(se, se2); !ok {
		t.Fatalf("Created and retrieved secrets do not match: %v %v", se, se2)
	}

	if err := sm.DeleteSecret(context.GetTestRequestContext(), id2); err != nil {
		t.Fatalf("Failed to delete secret for id %v: %v", id2, err)
	}
}
