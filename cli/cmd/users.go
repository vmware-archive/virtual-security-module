// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cmd

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

const (
	usersCmdUsage      = "users [sub-command]"
	createUserCmdUsage = "create [username] [public-key-filename]"
	deleteUserCmdUsage = "delete [username]"
	getUserCmdUsage    = "get [username]"
)

func init() {
	usersCmd.AddCommand(createUserCmd)
	usersCmd.AddCommand(deleteUserCmd)
	usersCmd.AddCommand(getUserCmd)

	RootCmd.AddCommand(usersCmd)
}

var usersCmd = &cobra.Command{
	Use:   usersCmdUsage,
	Short: "User management",
	Long:  "Create, get or delete a user",
}

var createUserCmd = &cobra.Command{
	Use:   createUserCmdUsage,
	Short: "Create a user",
	Long:  "Create a user",
	Run:   createUser,
}

var deleteUserCmd = &cobra.Command{
	Use:   deleteUserCmdUsage,
	Short: "Delete a user",
	Long:  "Delete a user",
	Run:   deleteUser,
}

var getUserCmd = &cobra.Command{
	Use:   getUserCmdUsage,
	Short: "Get a user's info",
	Long:  "Get a user's info",
	Run:   getUser,
}

func createUser(cmd *cobra.Command, args []string) {
	username, pubKey, err := createUserCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	id, err := apiCreateUser(username, pubKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("User created successfully")
	fmt.Printf("Id: %v\n", id)
}

func deleteUser(cmd *cobra.Command, args []string) {
	username, err := deleteUserCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = apiDeleteUser(username)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("User deleted successfully")
}

func getUser(cmd *cobra.Command, args []string) {
	username, err := getUserCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ue, err := apiGetUser(username)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	s, err := util.JSONPrettyPrint(ue)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(s)
}

func createUserCheckUsage(args []string) (string, *rsa.PublicKey, error) {
	if len(args) != 2 {
		return "", nil, fmt.Errorf("Usage: %v", createUserCmdUsage)
	}

	username := args[0]
	pubKeyFilename := args[1]

	rsaPubKey, err := util.ReadRSAPublicKey(pubKeyFilename)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read public key: %v", err)
	}

	return username, rsaPubKey, nil
}

func deleteUserCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", deleteUserCmdUsage)
	}

	username := args[0]

	return username, nil
}

func getUserCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", getUserCmdUsage)
	}

	username := args[0]

	return username, nil
}

func apiCreateUser(username string, pubKey *rsa.PublicKey) (string, error) {
	if Token == "" {
		return "", fmt.Errorf("authn token is empty")
	}

	creds, err := json.Marshal(pubKey)
	if err != nil {
		return "", err
	}

	ue := &model.UserEntry{
		Username:    username,
		Credentials: creds,
	}

	body := new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(ue)
	if err != nil {
		return "", err
	}

	usersUrl := fmt.Sprintf("%v/users", Url)
	req, err := http.NewRequest("POST", usersUrl, body)
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

func apiDeleteUser(username string) error {
	if Token == "" {
		return fmt.Errorf("authn token is empty")
	}

	deleteUrl := fmt.Sprintf("%v/users/%v", Url, username)
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

func apiGetUser(username string) (*model.UserEntry, error) {
	if Token == "" {
		return nil, fmt.Errorf("authn token is empty")
	}

	getUrl := fmt.Sprintf("%v/users/%v", Url, username)
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

	var userEntry model.UserEntry
	if err = json.NewDecoder(resp.Body).Decode(&userEntry); err != nil {
		return nil, err
	}

	return &userEntry, nil
}
