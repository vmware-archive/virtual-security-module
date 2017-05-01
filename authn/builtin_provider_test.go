// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

var p *BuiltinProvider

func builtinProviderTestSetup() {
	p = NewBuiltinProvider()
	if err := p.Init(nil, vds.NewInMemoryDS(), vks.NewInMemoryKS()); err != nil {
		fmt.Printf("Failed to initialize builtin provider: %v\n", err)
		os.Exit(1)
	}
}

func builtinProviderTestCleanup() {
	p = nil
}

func TestCreateUserAndLogin(t *testing.T) {
	username := "testuser-0"
	_, privateKey, err := createUser(username)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = login(username, privateKey, false)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	if err := p.DeleteUser(username); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func TestLoginWrongCredentials(t *testing.T) {
	username := "testuser-0"
	_, _, err := createUser(username)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = login(username, nil, false)
	if err == nil {
		t.Fatalf("Succeeded to login without the private key")
	}

	if err := p.DeleteUser(username); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func TestLoginNonExistentUser(t *testing.T) {
	username0 := "testuser-0"
	username1 := "testuser-1"

	_, privateKey, err := createUser(username0)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = login(username1, privateKey, false)
	if err == nil {
		t.Fatalf("Succeeded to login with non existent user")
	}

	if err := p.DeleteUser(username0); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func TestLoginCredentialsOfAnotherUser(t *testing.T) {
	username0 := "testuser-0"
	username1 := "testuser-1"

	_, _, err := createUser(username0)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, privateKey1, err := createUser(username1)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = login(username0, privateKey1, false)
	if err == nil {
		t.Fatalf("Succeeded to login with credentials of a different user")
	}

	if err := p.DeleteUser(username0); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	if err := p.DeleteUser(username1); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func TestLoginSkipFirstPhase(t *testing.T) {
	username := "testuser-0"
	_, privateKey, err := createUser(username)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = login(username, privateKey, true)
	if err == nil {
		t.Fatalf("Succeeded to login despite skipping first phase")
	}

	if err := p.DeleteUser(username); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func TestCreateUserAndGet(t *testing.T) {
	username := "testuser-0"
	ue, _, err := createUser(username)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	ue2, err := p.GetUser(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if !reflect.DeepEqual(ue, ue2) {
		t.Fatalf("Created and retrieved users are different: %v %v", ue, ue2)
	}

	if err := p.DeleteUser(username); err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
}

func createUser(username string) (*model.UserEntry, *rsa.PrivateKey, error) {
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

	id, err := p.CreateUser(ue)
	if err != nil {
		return nil, nil, err
	}
	if len(id) == 0 {
		return nil, nil, fmt.Errorf("Failed to create user %v: returned id is empty", username)
	}

	return ue, privateKey, nil
}

func login(username string, privateKey *rsa.PrivateKey, skipFirstPhase bool) (string, error) {
	// login - first pass: get a challenge
	loginRequest := &model.LoginRequest{
		Username: username,
	}

	encryptedChallenge := []byte{}
	if !skipFirstPhase {
		var err error
		encodedChallenge, err := p.Login(loginRequest)
		if err != nil {
			return "", err
		}

		encryptedChallenge, err = base64.StdEncoding.DecodeString(encodedChallenge)
		if err != nil {
			return "", err
		}
	}

	// decrypt challenge using private key
	pk := privateKey
	if pk == nil {
		// no private key is given - generate a fake one for testing
		var err error
		pk, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
	}
	challenge, err := rsa.DecryptPKCS1v15(nil, pk, encryptedChallenge)
	if err != nil {
		return "", err
	}

	// login - second phase: send the decrypted challenge
	loginRequest.Challenge = string(challenge)
	token, err := p.Login(loginRequest)
	if err != nil {
		return "", err
	}

	if len(token) == 0 {
		return "", fmt.Errorf("Failed to login - second phase: returned token is empty")
	}

	return token, nil
}
