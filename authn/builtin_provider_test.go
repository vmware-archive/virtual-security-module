// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

var p *BuiltinProvider

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
	
	p = NewBuiltinProvider()
	if err := p.Init(nil, ds, ks); err != nil {
		fmt.Printf("Failed to initialize builtin provider: %v\n", err)
		os.Exit(1)
	}

	/*
	apiTestSetup()
	defer apiTestCleanup()
	*/
	
	os.Exit(m.Run())
}

func TestCreateUserAndLogin(t *testing.T) {
	// create a user
	username := "testuser-0"
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	creds, err := json.Marshal(privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	ue := &model.UserEntry{
		Username: username,
		Credentials: creds,
	}

	id, err := p.CreateUser(ue)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	if len(id) == 0 {
		t.Fatalf("Failed to create secret: returned id is empty")
	}
	
	// login - first pass: get a challenge
	loginRequest := &model.LoginRequest{
		Username: username,
	}
	encryptedChallenge, err := p.Login(loginRequest)
	if err != nil {
		t.Fatalf("Failed to login - first phase: %v", err)
	}
	
	// decrypt challenge using private key
	challenge, err := rsa.DecryptPKCS1v15(nil, privateKey, []byte(encryptedChallenge))
	if err != nil {
		t.Fatalf("Failed to decrypt challenge using private key: %v", err)
	}
	
	// login - second phase: send the decrypted challenge
	loginRequest.Challenge = string(challenge)
	token, err := p.Login(loginRequest)
	if err != nil {
		t.Fatalf("Failed to login - second phase: %v", err)
	}
	
	if len(token) == 0 {
		t.Fatalf("Failed to login - second phase: returned token is empty", err)
	}
}

func TestLoginWrongCredentials(t *testing.T) {
	// TODO
}

func TestLoginNonExistentUser(t *testing.T) {
	// TODO
}

func TestLoginCredentialsOfAnotherUser(t *testing.T) {
	// TODO
}

func TestLoginSkipFirstPhase(t *testing.T) {
	// TODO
}