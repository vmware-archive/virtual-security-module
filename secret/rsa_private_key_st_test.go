// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
)

func TestCreateAndGetRSAPrivateKeySecret(t *testing.T) {
	secretMetaData := fmt.Sprintf("{\"keyLength\": %v}", 2048)

	se := &model.SecretEntry{
		Id:             "id1",
		Type:           RSAPrivateKeySecretTypeName,
		MetaData:       secretMetaData,
		SecretData:     []byte{},
		Owner:          "user0",
		ExpirationTime: time.Now().Add(time.Hour),
	}

	id, err := sm.CreateSecret(context.GetTestRequestContext(), se)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	if len(id) == 0 {
		t.Fatalf("Failed to create secret: returned id is empty")
	}

	se2, err := sm.GetSecret(context.GetTestRequestContext(), id)
	if err != nil {
		t.Fatalf("Failed to get secret for id %v: %v", id, err)
	}

	block, _ := pem.Decode(se2.SecretData)
	if block == nil {
		t.Fatalf("Failed to decode returned private key: %v", err)
	}

	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse returned key as RSA private key: %v", err)
	}

	if err := sm.DeleteSecret(context.GetTestRequestContext(), id); err != nil {
		t.Fatalf("Failed to delete secret for id %v: %v", id, err)
	}
}
