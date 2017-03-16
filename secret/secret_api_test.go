// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
)

var ts *httptest.Server

func apiTestSetup() {
	mux := denco.NewMux()
	handlers := sm.RegisterEndpoints(mux)
	handler, err := mux.Build(handlers)
	if err != nil {
		fmt.Printf("Failed to create RESTful API: %v", err)
		os.Exit(1)
	}

	ts = httptest.NewServer(handler)
}

func apiTestCleanup() {
	ts.Close()
}

func TestAPICreateAndGetSecretProvidedId(t *testing.T) {
	testAPICreateAndGetSecret(t, "api-id0")
}

func TestAPICreateAndGetSecret(t *testing.T) {
	testAPICreateAndGetSecret(t, "")
}

func testAPICreateAndGetSecret(t *testing.T, id string) {
	// step 1: create and send secret creation request
	expirationTime := time.Now().Add(time.Hour)

	se := &model.SecretEntry{
		Id:                     id,
		SecretData:             []byte("secret0"),
		OwnerEntryId:           "user0",
		NamespaceEntryId:       "root",
		ExpirationTime:         expirationTime,
		AuthorizationPolicyIds: []string{},
	}
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(se)
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

	// step 2: get created secret by id and compare to originally created secret
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

	if id == "" {
		se.Id = creationResponse.Id
	}
	if !reflect.DeepEqual(se, &se2) {
		t.Fatalf("Created and retrieved secrets are different: %v %v", se, se2)
	}
}
