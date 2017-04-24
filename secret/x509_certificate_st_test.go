// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
)

func TestCreateAndGetX509CertificateSecret(t *testing.T) {
	privKeyId, err := createPrivKey()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	secretMetaData := X509CertificateSecretMetaData{
		CommonName:         "test.example.com",
		Organization:       "Test Examples",
		OrganizationalUnit: "",
		Country:            "IL",
		Locality:           "",
		PrivateKeyId:       privKeyId,
	}

	secretMetaDataBytes, err := json.Marshal(secretMetaData)
	if err != nil {
		t.Fatalf("Failed to json marshal secret meta-data: %v", err)
	}

	se := &model.SecretEntry{
		Id:             "id1",
		Type:           X509CertificateSecretTypeName,
		MetaData:       string(secretMetaDataBytes),
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

	_, err = sm.GetSecret(context.GetTestRequestContext(), id)
	if err != nil {
		t.Fatalf("Failed to get secret for id %v: %v", id, err)
	}

	if err := sm.DeleteSecret(context.GetTestRequestContext(), id); err != nil {
		t.Fatalf("Failed to delete secret for id %v: %v", id, err)
	}

	if err := deletePrivKey(privKeyId); err != nil {
		t.Fatalf("Failed to private key with id %v: %v", privKeyId, err)
	}
}

func createPrivKey() (string, error) {
	secretMetaData := fmt.Sprintf("{\"keyLength\": %v}", 2048)

	se := &model.SecretEntry{
		Id:             "priv-key-id1",
		Type:           RSAPrivateKeySecretTypeName,
		MetaData:       secretMetaData,
		SecretData:     []byte{},
		Owner:          "user0",
		ExpirationTime: time.Now().Add(time.Hour),
	}

	return sm.CreateSecret(context.GetTestRequestContext(), se)
}

func deletePrivKey(id string) error {
	return sm.DeleteSecret(context.GetTestRequestContext(), id)
}
