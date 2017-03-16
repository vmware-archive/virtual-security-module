// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"os"
	
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

var am *AuthnManager

func TestMain(m *testing.M) {
	cfg := config.GenerateTestConfig()
	
	ds, err := vds.GetDataStoreFromConfig(cfg)
	if err != nil {
		fmt.Printf("Failed to get data store from config: %v\n", err)
		os.Exit(1)
	}
	
	ks, err := vks.GetKeyStoreFromConfig(cfg)
	if err != nil {
		fmt.Printf("Failed to get key store from config: %v\n", err)
		os.Exit(1)
	}
	
	am = New()
	if err := am.Init(nil, ds, ks); err != nil {
		fmt.Printf("Failed to initialize authn manager: %v\n", err)
		os.Exit(1)
	}

	builtinProviderTestSetup()
	defer builtinProviderTestCleanup()
	
	apiTestSetup()
	defer apiTestCleanup()
	
	os.Exit(m.Run())
}

func TestWhitelist(t *testing.T) {
	r := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	admitted := am.HandlePre(w, r)
	if !admitted {
		t.Fatalf("not admitted to /login, which is in whitelist")
	}
	
	r = httptest.NewRequest("POST", "/users", nil)
	w = httptest.NewRecorder()
	admitted = am.HandlePre(w, r)
	if admitted {
		t.Fatalf("admitted to /users without a token")
	}
	
	username := "testuser-0"
	_, privateKey , err := amCreateUser(username)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	
	token, err := amLogin(username, privateKey)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	
	r = httptest.NewRequest("POST", "/users", nil)
	r.Header.Add(HeaderNameAuth, fmt.Sprintf("Bearer: %v", token))
	w = httptest.NewRecorder()
	admitted = am.HandlePre(w, r)
	if !admitted {
		t.Fatalf("not admitted to /users with a valid token")
	}
	
	if err := amDeleteUser(username); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func amCreateUser(username string) (*model.UserEntry, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	
	creds, err := json.Marshal(privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	ue := &model.UserEntry{
		Username: username,
		Credentials: creds,
	}

	id, err := am.CreateUser(ue)
	if err != nil {
		return nil, nil, err
	}
	if len(id) == 0 {
		return nil, nil, fmt.Errorf("Failed to create user %v: returned id is empty", username)
	}
	
	return ue, privateKey, nil
}

func amDeleteUser(username string) error {
	return am.DeleteUser(username)
}

func amLogin(username string, privateKey *rsa.PrivateKey) (string, error) {
	// login - first pass: get a challenge
	loginRequest := &model.LoginRequest{
		Username: username,
	}
	
	encodedChallenge, err := am.Login(loginRequest)
	if err != nil {
		return "", err
	}
	
	encryptedChallenge, err := base64.StdEncoding.DecodeString(encodedChallenge)
	if err != nil {
		return "", err
	}
	
	// decrypt challenge using private key
	challenge, err := rsa.DecryptPKCS1v15(nil, privateKey, encryptedChallenge)
	if err != nil {
		return "", err
	}
	
	// login - second phase: send the decrypted challenge
	loginRequest.Challenge = string(challenge)
	token, err := am.Login(loginRequest)
	if err != nil {
		return "", err
	}
	
	if len(token) == 0 {
		return "", fmt.Errorf("Failed to login - second phase: returned token is empty")
	}
	
	return token, nil
}
