// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/secret"
	"github.com/vmware/virtual-security-module/util"
)

const (
	secretsCmdUsage      = "secrets [sub-command]"
	createSecretCmdUsage = "create secret-id secret-data"
	deleteSecretCmdUsage = "delete secret-id"
	getSecretCmdUsage    = "get secret-id"
)

func init() {
	secretsCmd.AddCommand(createSecretCmd)
	secretsCmd.AddCommand(deleteSecretCmd)
	secretsCmd.AddCommand(getSecretCmd)

	RootCmd.AddCommand(secretsCmd)
}

var secretsCmd = &cobra.Command{
	Use:   secretsCmdUsage,
	Short: "Secret management",
	Long:  "Create, get or delete a secret",
}

var createSecretCmd = &cobra.Command{
	Use:   createSecretCmdUsage,
	Short: "Create a secret",
	Long:  "Create a secret",
	Run:   createSecret,
}

var deleteSecretCmd = &cobra.Command{
	Use:   deleteSecretCmdUsage,
	Short: "Delete a secret",
	Long:  "Delete a secret",
	Run:   deleteSecret,
}

var getSecretCmd = &cobra.Command{
	Use:   getSecretCmdUsage,
	Short: "Get a secret",
	Long:  "Get a secret",
	Run:   getSecret,
}

func createSecret(cmd *cobra.Command, args []string) {
	secretId, secretData, err := createSecretCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	id, err := apiCreateSecret(secretId, secretData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Secret created successfully")
	fmt.Printf("Id: %v\n", id)
}

func deleteSecret(cmd *cobra.Command, args []string) {
	secretId, err := deleteSecretCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = apiDeleteSecret(secretId)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Secret deleted successfully")
}

func getSecret(cmd *cobra.Command, args []string) {
	secretId, err := getSecretCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	se, err := apiGetSecret(secretId)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	s, err := util.JSONPrettyPrint(se)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(s)
	fmt.Printf("Secret data: %v\n", string(se.SecretData))
}

func createSecretCheckUsage(args []string) (string, string, error) {
	if len(args) != 2 {
		return "", "", fmt.Errorf("Usage: %v", createSecretCmdUsage)
	}

	secretId := args[0]
	secretData := args[1]

	return secretId, secretData, nil
}

func deleteSecretCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", deleteSecretCmdUsage)
	}

	secretId := args[0]

	return secretId, nil
}

func getSecretCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", getSecretCmdUsage)
	}

	secretId := args[0]

	return secretId, nil
}

func apiCreateSecret(secretId, secretData string) (string, error) {
	if Token == "" {
		return "", fmt.Errorf("authn token is empty")
	}

	se := &model.SecretEntry{
		Id:         secretId,
		Type:       secret.DataSecretTypeName,
		SecretData: []byte(secretData),
	}

	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(se)
	if err != nil {
		return "", err
	}

	secretsUrl := fmt.Sprintf("%v/secrets", Url)
	req, err := http.NewRequest("POST", secretsUrl, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", Token))

	client, err := httpClient()
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
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

func apiDeleteSecret(secretId string) error {
	if Token == "" {
		return fmt.Errorf("authn token is empty")
	}

	deleteUrl := fmt.Sprintf("%v/secrets/%v", Url, secretId)
	req, err := http.NewRequest("DELETE", deleteUrl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", Token))

	client, err := httpClient()
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Response status is different than 204 StatusNoContent: %v", resp.Status)
	}

	return nil
}

func apiGetSecret(secretId string) (*model.SecretEntry, error) {
	if Token == "" {
		return nil, fmt.Errorf("authn token is empty")
	}

	getUrl := fmt.Sprintf("%v/secrets/%v", Url, secretId)
	req, err := http.NewRequest("GET", getUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", Token))

	client, err := httpClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status is different than 200 StatusOK: %v", resp.Status)
	}

	var secretEntry model.SecretEntry
	if err = json.NewDecoder(resp.Body).Decode(&secretEntry); err != nil {
		return nil, err
	}

	return &secretEntry, nil
}
