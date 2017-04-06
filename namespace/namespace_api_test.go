// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package namespace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
)

var ts *httptest.Server

func apiTestSetup() {
	mux := denco.NewMux()
	handlers := nm.RegisterEndpoints(mux)
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

func TestAPICreateAndGetRootNamespace(t *testing.T) {
	rootNS := "/namespace0"
	id, err := apiCreateNamespace(rootNS)
	if err != nil {
		t.Fatalf("Failed to create namespace: %v", err)
	}

	_, err = apiGetNamespace(id)
	if err != nil {
		t.Fatalf("Failed to get namespace: %v", err)
	}

	if err := apiDeleteNamespace(id); err != nil {
		t.Fatalf("Failed to delete namespace: %v", err)
	}
}

func TestAPICreateAndGetChildNamespace(t *testing.T) {
	rootNS := "/namespace0"
	childNS := "/namespace0/child"
	grandchildNS := "/namespace0/child/grandchild"

	if _, err := apiCreateNamespace(rootNS); err != nil {
		t.Fatalf("Failed to create namespace: %v", err)
	}

	if _, err := apiCreateNamespace(childNS); err != nil {
		t.Fatalf("Failed to create namespace: %v", err)
	}

	if _, err := apiCreateNamespace(grandchildNS); err != nil {
		t.Fatalf("Failed to create namespace: %v", err)
	}

	if _, err := apiGetNamespace(rootNS); err != nil {
		t.Fatalf("Failed to get namespace: %v", err)
	}

	if _, err := apiGetNamespace(childNS); err != nil {
		t.Fatalf("Failed to get namespace: %v", err)
	}

	if _, err := apiGetNamespace(grandchildNS); err != nil {
		t.Fatalf("Failed to get namespace: %v", err)
	}

	if err := apiDeleteNamespace(grandchildNS); err != nil {
		t.Fatalf("Failed to delete namespace: %v", err)
	}

	if err := apiDeleteNamespace(childNS); err != nil {
		t.Fatalf("Failed to delete namespace: %v", err)
	}

	if err := apiDeleteNamespace(rootNS); err != nil {
		t.Fatalf("Failed to delete namespace: %v", err)
	}
}

func TestAPINamespaceNavigation(t *testing.T) {
	if _, err := apiCreateNamespace("/namespace0"); err != nil {
		t.Fatalf("Failed to create namespace: %v", err)
	}

	childCount := 3
	for i := 0; i < childCount; i++ {
		path := fmt.Sprintf("/namespace0/%v", i)
		if _, err := apiCreateNamespace(path); err != nil {
			t.Fatalf("Failed to create namespace: %v", err)
		}
	}

	root2, err := apiGetNamespace("/namespace0")
	if err != nil {
		t.Fatalf("Failed to get namespace: %v", err)
	}

	if len(root2.ChildPaths) != childCount {
		t.Fatalf("Root namespace has different number of children %v than expected: %v", len(root2.ChildPaths), childCount)
	}

	for _, path := range root2.ChildPaths {
		if _, err := apiGetNamespace(path); err != nil {
			t.Fatalf("Failed to get namespace: %v", err)
		}

		if err := apiDeleteNamespace(path); err != nil {
			t.Fatalf("Failed to delete namespace: %v", err)
		}
	}

	if err := apiDeleteNamespace("/namespace0"); err != nil {
		t.Fatalf("Failed to delete namespace: %v", err)
	}
}

func apiCreateNamespace(path string) (string, error) {
	ne := &model.NamespaceEntry{
		Path: path,
	}

	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(ne)
	if err != nil {
		return "", err
	}

	testUrl := fmt.Sprintf("%v/namespaces", ts.URL)
	resp, err := http.Post(testUrl, "application/json", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("Response status is different than 201 StatusCreated: %v", resp.Status)
	}

	var creationResponse model.CreationResponse
	if err = json.NewDecoder(resp.Body).Decode(&creationResponse); err != nil {
		return "", err
	}
	if len(creationResponse.Id) == 0 {
		return "", fmt.Errorf("returned id is empty")
	}

	return creationResponse.Id, nil
}

func apiDeleteNamespace(path string) error {
	testUrl := fmt.Sprintf("%v/namespaces%v", ts.URL, path)
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

func apiGetNamespace(path string) (*model.NamespaceEntry, error) {
	testUrl := fmt.Sprintf("%v/namespaces%v", ts.URL, path)
	resp, err := http.Get(testUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status is different than 200 StatusOK: %v", resp.Status)
	}

	var namespaceEntry model.NamespaceEntry
	if err = json.NewDecoder(resp.Body).Decode(&namespaceEntry); err != nil {
		return nil, err
	}
	if path != namespaceEntry.Path {
		return nil, fmt.Errorf("returned namespace path %v is different than expect: %v", namespaceEntry.Path, path)
	}

	return &namespaceEntry, nil
}
