// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/secret"
	"github.com/vmware/virtual-security-module/util"
)

const (
	secretsCmdUsage      = "secrets [sub-command]"
	createSecretCmdUsage = "create secret"
	deleteSecretCmdUsage = "delete secret-id"
	getSecretCmdUsage    = "get secret-id"

	createDataSecretCmdUsage            = "data secret-id secret-data"
	createRSAPrivateKeySecretCmdUsage   = "rsa-private-key secret-id key-length"
	createX509CertificateSecretCmdUsage = "x509-certificate secret-id private-key-id common-name organization country"
)

func init() {
	createSecretCmd.AddCommand(createDataSecretCmd)
	createSecretCmd.AddCommand(createRSAPrivateKeySecretCmd)
	createSecretCmd.AddCommand(createX509CertificateSecretCmd)

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

var createDataSecretCmd = &cobra.Command{
	Use:   createDataSecretCmdUsage,
	Short: "Create a data secret",
	Long:  "Create a data secret",
	Run:   createDataSecret,
}

var createRSAPrivateKeySecretCmd = &cobra.Command{
	Use:   createRSAPrivateKeySecretCmdUsage,
	Short: "Create a rsa-private-key secret",
	Long:  "Create a rsa-private-key secret",
	Run:   createRSAPrivateKeySecret,
}

var createX509CertificateSecretCmd = &cobra.Command{
	Use:   createX509CertificateSecretCmdUsage,
	Short: "Create a x509-certificate secret",
	Long:  "Create a x509-certificate secret",
	Run:   createX509CertificateSecret,
}

func createDataSecret(cmd *cobra.Command, args []string) {
	secretId, secretData, err := createDataSecretCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	id, err := apiCreateDataSecret(secretId, secretData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Secret created successfully")
	fmt.Printf("Id: %v\n", id)
}

func createRSAPrivateKeySecret(cmd *cobra.Command, args []string) {
	secretId, keyLength, err := createRSAPrivateKeySecretCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	id, err := apiCreateRSAPrivateKeySecret(secretId, keyLength)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Secret created successfully")
	fmt.Printf("Id: %v\n", id)
}

func createX509CertificateSecret(cmd *cobra.Command, args []string) {
	secretId, privateKeyId, commonName, organization, country, err := createX509CertificateSecretCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	id, err := apiCreateX509CertificateSecret(secretId, privateKeyId, commonName, organization, country)
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

	fmt.Printf("\nDecoded Secret data:\n")
	fmt.Printf("%s\n", se.SecretData)
}

func createDataSecretCheckUsage(args []string) (string, string, error) {
	if len(args) != 2 {
		return "", "", fmt.Errorf("Usage: %v", createDataSecretCmdUsage)
	}

	secretId := args[0]
	secretData := args[1]

	return secretId, secretData, nil
}

func createRSAPrivateKeySecretCheckUsage(args []string) (string, int, error) {
	if len(args) != 2 {
		return "", 0, fmt.Errorf("Usage: %v", createRSAPrivateKeySecretCmdUsage)
	}

	secretId := args[0]
	keyLengthStr := args[1]

	keyLength, err := strconv.Atoi(keyLengthStr)
	if err != nil {
		return "", 0, fmt.Errorf("failed to convert %s to an int: %v", keyLengthStr, err)
	}

	return secretId, keyLength, nil
}

func createX509CertificateSecretCheckUsage(args []string) (string, string, string, string, string, error) {
	if len(args) != 5 {
		return "", "", "", "", "", fmt.Errorf("Usage: %v", createX509CertificateSecretCmdUsage)
	}

	secretId := args[0]
	privKeyId := args[1]
	commonName := args[2]
	organization := args[3]
	country := args[4]

	return secretId, privKeyId, commonName, organization, country, nil
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

func apiCreateDataSecret(secretId, secretData string) (string, error) {
	return apiCreateSecret(secretId, secret.DataSecretTypeName, "{}", []byte(secretData))
}

func apiCreateRSAPrivateKeySecret(secretId string, keyLength int) (string, error) {
	secretMetaData := fmt.Sprintf("{\"keyLength\": %v}", keyLength)
	return apiCreateSecret(secretId, secret.RSAPrivateKeySecretTypeName, secretMetaData, []byte{})
}

func apiCreateX509CertificateSecret(secretId, privKeyId, commonName, organization, country string) (string, error) {
	secretMetaData := secret.X509CertificateSecretMetaData{
		CommonName:         commonName,
		Organization:       organization,
		OrganizationalUnit: "",
		Country:            country,
		Locality:           "",
		PrivateKeyId:       privKeyId,
	}

	secretMetaDataBytes, err := json.Marshal(secretMetaData)
	if err != nil {
		return "", err
	}

	return apiCreateSecret(secretId, secret.X509CertificateSecretTypeName, string(secretMetaDataBytes), []byte{})
}

func apiCreateSecret(secretId, secretType, secretMetaData string, secretData []byte) (string, error) {
	if Token == "" {
		return "", fmt.Errorf("authn token is empty")
	}

	se := &model.SecretEntry{
		Id:         secretId,
		Type:       secretType,
		MetaData:   secretMetaData,
		SecretData: secretData,
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
