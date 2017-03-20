// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cmd

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

const usage = "login [username] [private-key-filename]"

func init() {
	RootCmd.AddCommand(loginCmd)
}

var loginCmd = &cobra.Command{
	Use:   usage,
	Short: "Login to the server",
	Long: `Login to the server by providing a username and credentials. Upon
successful login, a JWT token would be printed. Use this token in your
further interactions with the server.`,
	Run: login,
}

func login(cmd *cobra.Command, args []string) {
	username, privKey, err := loginCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	token, err := apiLogin(username, privKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Login successful")
	fmt.Printf("Token: %v\n", token)
}

func loginCheckUsage(args []string) (string, *rsa.PrivateKey, error) {
	if len(args) != 2 {
		return "", nil, fmt.Errorf("Usage: %v", usage)
	}

	username := args[0]
	privKeyFilename := args[1]

	rsaPrivKey, err := util.ReadRSAPrivateKey(privKeyFilename)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read private key: %v", err)
	}

	return username, rsaPrivKey, nil
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

	loginUrl := fmt.Sprintf("%v/login", Url)
	resp, err := http.Post(loginUrl, "application/json", body)
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

	resp, err = http.Post(loginUrl, "application/json", body)
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
