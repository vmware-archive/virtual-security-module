// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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
	handlers := am.RegisterEndpoints(mux)
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

func TestAPICreateUserAndLogin(t *testing.T) {
	username := "testuser-0"
	_, privateKey, err := apiCreateUser(username)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = apiLogin(username, privateKey)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	if err := apiDeleteUser(username); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func TestAPICreateUserAndGet(t *testing.T) {
	username := "testuser-0"
	ue, _, err := apiCreateUser(username)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	ue2, err := apiGetUser(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if !reflect.DeepEqual(ue, ue2) {
		t.Fatalf("Created and retrieved users are different: %v %v", ue, ue2)
	}

	if err := apiDeleteUser(username); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func apiCreateUser(username string) (*model.UserEntry, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	creds, err := json.Marshal(privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	ue := &model.UserEntry{
		Username:    username,
		Credentials: creds,
		Roles:       []model.RoleEntry{},
	}

	body := new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(ue)
	if err != nil {
		return nil, nil, err
	}

	testUrl := fmt.Sprintf("%v/users", ts.URL)
	resp, err := http.Post(testUrl, "application/json", body)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, nil, fmt.Errorf("Response status is different than 201 StatusCreated: %v", resp.Status)
	}

	var creationResponse model.CreationResponse
	if err = json.NewDecoder(resp.Body).Decode(&creationResponse); err != nil {
		return nil, nil, err
	}
	if len(creationResponse.Id) == 0 {
		return nil, nil, fmt.Errorf("returned id is empty")
	}

	return ue, privateKey, nil
}

func apiDeleteUser(username string) error {
	testUrl := fmt.Sprintf("%v/users/%v", ts.URL, username)
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

func apiGetUser(username string) (*model.UserEntry, error) {
	testUrl := fmt.Sprintf("%v/users/%v", ts.URL, username)
	resp, err := http.Get(testUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status is different than 200 StatusOK: %v", resp.Status)
	}

	var userEntry model.UserEntry
	if err = json.NewDecoder(resp.Body).Decode(&userEntry); err != nil {
		return nil, err
	}
	if username != userEntry.Username {
		return nil, fmt.Errorf("returned username %v is different than expect: %v", userEntry.Username, username)
	}

	return &userEntry, nil
}

func apiLogin(username string, privateKey *rsa.PrivateKey) (string, error) {
	// login - first pass: get a challenge
	loginRequest := &model.LoginRequest{
		Username: username,
	}

	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(loginRequest)
	if err != nil {
		return "", err
	}

	testUrl := fmt.Sprintf("%v/login", ts.URL)
	resp, err := http.Post(testUrl, "application/json", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Response status is different than 200 StatusOK: %v", resp.Status)
	}

	var loginResponse model.LoginResponse
	if err = json.NewDecoder(resp.Body).Decode(&loginResponse); err != nil {
		return "", err
	}
	if len(loginResponse.ChallengeOrToken) == 0 {
		return "", fmt.Errorf("returned challenge is empty")
	}
	encodedChallenge := loginResponse.ChallengeOrToken

	encryptedChallenge, err := base64.StdEncoding.DecodeString(encodedChallenge)
	if err != nil {
		return "", err
	}

	// decrypt challenge using private key
	challenge, err := rsa.DecryptPKCS1v15(nil, privateKey, []byte(encryptedChallenge))
	if err != nil {
		return "", err
	}

	// login - second phase: send the decrypted challenge
	loginRequest.Challenge = string(challenge)
	body = new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(loginRequest)
	if err != nil {
		return "", err
	}

	resp, err = http.Post(testUrl, "application/json", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Response status is different than 200 StatusOK: %v", resp.Status)
	}

	var tokenResponse model.LoginResponse
	if err = json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}

	if len(tokenResponse.ChallengeOrToken) == 0 {
		return "", fmt.Errorf("returned token is empty")
	}

	return tokenResponse.ChallengeOrToken, nil
}
