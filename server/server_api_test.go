// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package server

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
	"testing"

	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

var ts *httptest.Server

func apiTestSetup() {
	if err := s.initHttpPipeline(); err != nil {
		fmt.Printf("Failed to init http pipeline: %v", err)
		os.Exit(1)
	}

	ts = httptest.NewServer(s.httpPipeline)
}

func apiTestCleanup() {
	ts.Close()
}

func TestCreateWithoutLogin(t *testing.T) {
	username := "testuser-0"
	_, _, err := apiCreateUser(username, "")
	if err == nil {
		t.Fatal("Succeeed to create user without being logged-in")
	}
}

func TestRootLoginCreateUserAndLogin(t *testing.T) {
	rootPrivKey, err := readTestRootPrivateKey()
	if err != nil {
		t.Fatalf("Root login failed: %v", err)
	}

	rootToken, err := apiLogin("root", rootPrivKey)
	if err != nil {
		t.Fatalf("Root login failed: %v", err)
	}

	username := "testuser-0"
	_, userPriveKey, err := apiCreateUser(username, rootToken)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	userToken, err := apiLogin(username, userPriveKey)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	if rootToken == userToken {
		t.Fatal("returned user token is the same as root token")
	}

	if err := apiDeleteUser(username, rootToken); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func readTestRootPrivateKey() (*rsa.PrivateKey, error) {
	rootInitPrivateKeyFile := tCfg.ServerConfig.RootInitPrivateKey
	rsaPrivKey, err := util.ReadRSAPrivateKey(rootInitPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read root key from file: %v", err)
	}

	return rsaPrivKey, nil
}

func apiCreateUser(username, token string) (*model.UserEntry, *rsa.PrivateKey, error) {
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
	}

	body := new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(ue)
	if err != nil {
		return nil, nil, err
	}

	testUrl := fmt.Sprintf("%v/users", ts.URL)
	req, err := http.NewRequest("POST", testUrl, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))
	}
	resp, err := http.DefaultClient.Do(req)
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

func apiDeleteUser(username, token string) error {
	testUrl := fmt.Sprintf("%v/users/%v", ts.URL, username)
	req, err := http.NewRequest("DELETE", testUrl, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))
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

func apiGetUser(username, token string) (*model.UserEntry, error) {
	testUrl := fmt.Sprintf("%v/users/%v", ts.URL, username)
	req, err := http.NewRequest("GET", testUrl, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))
	}
	resp, err := http.DefaultClient.Do(req)
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
