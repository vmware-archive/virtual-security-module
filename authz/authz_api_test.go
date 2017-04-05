// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
)

var ts *httptest.Server

func apiTestSetup() {
	mux := denco.NewMux()
	handlers := az.RegisterEndpoints(mux)
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

func TestAPICreatePolicyAndGet(t *testing.T) {
	policyId := "authz-policy-0"
	pe, err := apiCreatePolicy(policyId)
	if err != nil {
		t.Fatalf("Failed to create policy: %v", err)
	}

	pe2, err := apiGetPolicy(policyId)
	if err != nil {
		t.Fatalf("Failed to get policy: %v", err)
	}

	if !reflect.DeepEqual(pe, pe2) {
		t.Fatalf("Created and retrieved policies are different: %v %v", pe, pe2)
	}

	if err := apiDeletePolicy(policyId); err != nil {
		t.Fatalf("Failed to delete policy: %v", err)
	}
}

func apiCreatePolicy(policyId string) (*model.AuthorizationPolicyEntry, error) {
	pe := &model.AuthorizationPolicyEntry{
		Id:                policyId,
		RoleLabels:        []string{"admin"},
		AllowedOperations: []model.Operation{model.Operation{Label: model.OpCreate}},
		Owner:             "user0",
	}

	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(pe)
	if err != nil {
		return nil, err
	}

	testUrl := fmt.Sprintf("%v/authz/policies", ts.URL)
	resp, err := http.Post(testUrl, "application/json", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Response status is different than 201 StatusCreated: %v", resp.Status)
	}

	var creationResponse model.CreationResponse
	if err = json.NewDecoder(resp.Body).Decode(&creationResponse); err != nil {
		return nil, err
	}
	if len(creationResponse.Id) == 0 {
		return nil, fmt.Errorf("returned id is empty")
	}

	return pe, nil
}

func apiDeletePolicy(policyId string) error {
	testUrl := fmt.Sprintf("%v/authz/policies/%v", ts.URL, policyId)
	req, err := http.NewRequest("DELETE", testUrl, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Response status is different than 204 StatusNoContent: %v", resp.Status)
	}

	return nil
}

func apiGetPolicy(policyId string) (*model.AuthorizationPolicyEntry, error) {
	testUrl := fmt.Sprintf("%v/authz/policies/%v", ts.URL, policyId)
	resp, err := http.Get(testUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status is different than 200 StatusOK: %v", resp.Status)
	}

	var policyEntry model.AuthorizationPolicyEntry
	if err = json.NewDecoder(resp.Body).Decode(&policyEntry); err != nil {
		return nil, err
	}
	if policyId != policyEntry.Id {
		return nil, fmt.Errorf("returned policyId %v is different than expect: %v", policyEntry.Id, policyId)
	}

	return &policyEntry, nil
}
