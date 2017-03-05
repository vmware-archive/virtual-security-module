// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/vmware/virtual-security-module/model"
	"github.com/naoina/denco"
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
	duration, _ := time.ParseDuration("1h")
	expirationTime := time.Now().Add(duration)

	se := &model.SecretEntry{
		Id: id,
		SecretData: []byte("secret0"),
		OwnerEntryId: "user0",
		NamespaceEntryId: "root",
		ExpirationTime: expirationTime,
		AuthorizationPolicyIds: []string{},
	}
	body, err := json.Marshal(se)
	if err != nil {
		t.Fatalf("failed to marshal se %v: %v", se, err)
		return
	}

	testUrl := fmt.Sprintf("%v/secrets", ts.URL)
	resp, err := http.Post(testUrl, "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Response status is different than 201 StatusCreated: %v", resp.Status)
		return
	}

	creationResponseBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read secret creation response: %v", err)
		return
	}
	var creationResponse model.CreationResponse
	if err = json.Unmarshal(creationResponseBuf, &creationResponse); err != nil {
		t.Fatalf("Failed to parse secret creation response: %v", err)
		return
	}
	if len(creationResponse.Id) == 0 {
		t.Fatalf("Failed to create secret: returned id is empty")
		return
	}

	// step 2: get created secret by id and compare to originally created secret
	testUrl = fmt.Sprintf("%v/secrets/%v", ts.URL, creationResponse.Id)
	resp2, err := http.Get(testUrl)
	if err != nil {
		t.Fatalf("Failed to get secret with id %v: %v", creationResponse.Id, err)
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("Response status is different than 200 StatusOK: %v", resp2.Status)
		return
	}

	getResponseBuf, err := ioutil.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("Failed to read get secret response: %v", err)
		return
	}

	var se2 model.SecretEntry
	if err = json.Unmarshal(getResponseBuf, &se2); err != nil {
		t.Fatalf("Failed to parse get secret response: %v", err)
		return
	}

	if id == "" {
		se.Id = creationResponse.Id
	}
	if !reflect.DeepEqual(se, &se2) {
		t.Fatalf("Created and retrieved secrets are different: %v %v", se, se2)
		return
	}
}