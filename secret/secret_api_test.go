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

func TestAPICreateAndGetSecret(t *testing.T) {
	// step 1: create and send secret creation request
	expirationTime := time.Now().Add(time.Hour)

	se := &model.SecretEntry{
		Id:             "api-id0",
		SecretData:     []byte("secret0"),
		Owner:          "user0",
		ExpirationTime: expirationTime,
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

	if ok := model.SecretsEqual(se, &se2); !ok {
		t.Fatalf(err.Error())
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
}
