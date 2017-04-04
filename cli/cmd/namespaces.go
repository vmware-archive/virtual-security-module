// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

const (
	namespacesCmdUsage      = "namespaces [sub-command]"
	createNamespaceCmdUsage = "create namespace-path [owner] [role-labels]"
	deleteNamespaceCmdUsage = "delete namespace-path"
	getNamespaceCmdUsage    = "get namespace-path"
)

func init() {
	namespacesCmd.AddCommand(createNamespaceCmd)
	namespacesCmd.AddCommand(deleteNamespaceCmd)
	namespacesCmd.AddCommand(getNamespaceCmd)

	RootCmd.AddCommand(namespacesCmd)
}

var namespacesCmd = &cobra.Command{
	Use:   namespacesCmdUsage,
	Short: "Namespace management",
	Long:  "Create, get or delete a namespace",
}

var createNamespaceCmd = &cobra.Command{
	Use:   createNamespaceCmdUsage,
	Short: "Create a namespace",
	Long:  "Create a namespace",
	Run:   createNamespace,
}

var deleteNamespaceCmd = &cobra.Command{
	Use:   deleteNamespaceCmdUsage,
	Short: "Delete a namespace",
	Long:  "Delete a namespace",
	Run:   deleteNamespace,
}

var getNamespaceCmd = &cobra.Command{
	Use:   getNamespaceCmdUsage,
	Short: "Get a namespace",
	Long:  "Get a namespace",
	Run:   getNamespace,
}

func createNamespace(cmd *cobra.Command, args []string) {
	namespacePath, owner, roleLabels, err := createNamespaceCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	_, err = apiCreateNamespace(namespacePath, owner, roleLabels)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Namespace created successfully")
}

func deleteNamespace(cmd *cobra.Command, args []string) {
	namespacePath, err := deleteNamespaceCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = apiDeleteNamespace(namespacePath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Namespace deleted successfully")
}

func getNamespace(cmd *cobra.Command, args []string) {
	namespacePath, err := getNamespaceCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	ne, err := apiGetNamespace(namespacePath)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	s, err := util.JSONPrettyPrint(ne)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(s)
}

func createNamespaceCheckUsage(args []string) (string, string, []string, error) {
	if len(args) < 1 || len(args) > 3 {
		return "", "", []string{}, fmt.Errorf("Usage: %v", createNamespaceCmdUsage)
	}

	namespacePath := args[0]

	owner := ""
	if len(args) > 1 {
		owner = args[1]
	}

	roleLabels := []string{}
	if len(args) > 2 {
		roleLabels = strings.Split(args[2], ",")
	}

	return namespacePath, owner, roleLabels, nil
}

func deleteNamespaceCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", deleteNamespaceCmdUsage)
	}

	namespacePath := args[0]

	return namespacePath, nil
}

func getNamespaceCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", getNamespaceCmdUsage)
	}

	namespacePath := args[0]

	return namespacePath, nil
}

func apiCreateNamespace(path, owner string, roleLabels []string) (string, error) {
	if Token == "" {
		return "", fmt.Errorf("authn token is empty")
	}

	ne := &model.NamespaceEntry{
		Path:       path,
		Owner:      owner,
		RoleLabels: roleLabels,
	}

	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(ne)
	if err != nil {
		return "", err
	}

	namespacesUrl := fmt.Sprintf("%v/namespaces", Url)
	req, err := http.NewRequest("POST", namespacesUrl, body)
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

func apiDeleteNamespace(path string) error {
	if Token == "" {
		return fmt.Errorf("authn token is empty")
	}

	deleteUrl := fmt.Sprintf("%v/namespaces%v", Url, path)
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

func apiGetNamespace(path string) (*model.NamespaceEntry, error) {
	if Token == "" {
		return nil, fmt.Errorf("authn token is empty")
	}

	getUrl := fmt.Sprintf("%v/namespaces%v", Url, path)
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

	var namespaceEntry model.NamespaceEntry
	if err = json.NewDecoder(resp.Body).Decode(&namespaceEntry); err != nil {
		return nil, err
	}

	return &namespaceEntry, nil
}
