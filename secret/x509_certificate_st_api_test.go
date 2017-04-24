// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/vmware/virtual-security-module/model"
)

func TestAPICreateAndGetX509CertificateSecret(t *testing.T) {
	privKeyId, err := apiCreatePrivKey()
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
		Id:             "api-id0",
		Type:           X509CertificateSecretTypeName,
		MetaData:       string(secretMetaDataBytes),
		SecretData:     []byte{},
		Owner:          "user0",
		ExpirationTime: time.Now().Add(time.Hour),
	}

	body := new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(se)
	if err != nil {
		t.Fatalf("failed to marshal se %v: %v", se, err)
	}

	testUrl := fmt.Sprintf("%v/secrets", ts.URL)
	resp, err := http.Post(testUrl, "application/json", body)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Response status is different than 201 StatusCreated: %v", resp.Status)
	}

	var creationResponse model.CreationResponse
	if err = json.NewDecoder(resp.Body).Decode(&creationResponse); err != nil {
		t.Fatalf("Failed to parse secret creation response: %v", err)
	}

	if len(creationResponse.Id) == 0 {
		t.Fatalf("Failed to create secret: returned id is empty")
	}

	// step 2: get created secret by id and try to parse returned certificate
	testUrl = fmt.Sprintf("%v/secrets/%v", ts.URL, creationResponse.Id)
	resp2, err := http.Get(testUrl)
	if err != nil {
		t.Fatalf("Failed to get secret with id %v: %v", creationResponse.Id, err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Response status is different than 200 StatusOK: %v", resp2.Status)
	}

	var se2 model.SecretEntry
	if err = json.NewDecoder(resp2.Body).Decode(&se2); err != nil {
		t.Fatalf("Failed to parse get secret response: %v", err)
	}

	block, _ := pem.Decode(se2.SecretData)
	if block == nil {
		t.Fatalf("Failed to decode returned certificate: %v", err)
	}

	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse returned certificate: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Number of returned certificates is different than 1: %v", len(certs))
	}

	// cleanup: delete secret
	req, err := http.NewRequest("DELETE", testUrl, nil)
	if err != nil {
		t.Fatalf("Failed to dekete secret with id %v: %v", creationResponse.Id, err)
	}
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to dekete secret with id %v: %v", creationResponse.Id, err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusNoContent {
		t.Fatalf("Response status is different than 204 StatusNoContent: %v", resp3.Status)
	}

	if err := apiDeletePrivKey(privKeyId); err != nil {
		t.Fatalf("Failed to delete private key: %v", err)
	}
}

func apiCreatePrivKey() (string, error) {
	secretMetaData := fmt.Sprintf("{\"keyLength\": %v}", 2048)
	se := &model.SecretEntry{
		Id:             "api-id1",
		Type:           RSAPrivateKeySecretTypeName,
		MetaData:       secretMetaData,
		SecretData:     []byte{},
		Owner:          "user0",
		ExpirationTime: time.Now().Add(time.Hour),
	}
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(se)
	if err != nil {
		return "", fmt.Errorf("failed to marshal se %v: %v", se, err)
	}

	testUrl := fmt.Sprintf("%v/secrets", ts.URL)
	resp, err := http.Post(testUrl, "application/json", body)
	if err != nil {
		return "", fmt.Errorf("Failed to create secret: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("Response status is different than 201 StatusCreated: %v", resp.Status)
	}

	var creationResponse model.CreationResponse
	if err = json.NewDecoder(resp.Body).Decode(&creationResponse); err != nil {
		return "", fmt.Errorf("Failed to parse secret creation response: %v", err)
	}

	if len(creationResponse.Id) == 0 {
		return "", fmt.Errorf("Failed to create secret: returned id is empty")
	}

	return creationResponse.Id, nil
}

func apiDeletePrivKey(id string) error {
	testUrl := fmt.Sprintf("%v/secrets/%s", ts.URL, id)
	req, err := http.NewRequest("DELETE", testUrl, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete secret with id %v: %v", id, err)
	}
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to delete secret with id %v: %v", id, err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Response status is different than 204 StatusNoContent: %v", resp3.Status)
	}

	return nil
}
