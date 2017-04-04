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
	authzPoliciesCmdUsage     = "authz [sub-command]"
	createAuthzPolicyCmdUsage = "create policy-id role-labels allowed-operations [owner]"
	deleteAuthzPolicyCmdUsage = "delete policy-id"
	getAuthzPolicyCmdUsage    = "get policy-id"
)

func init() {
	authzPoliciesCmd.AddCommand(createAuthzPolicyCmd)
	authzPoliciesCmd.AddCommand(deleteAuthzPolicyCmd)
	authzPoliciesCmd.AddCommand(getAuthzPolicyCmd)

	RootCmd.AddCommand(authzPoliciesCmd)
}

var authzPoliciesCmd = &cobra.Command{
	Use:   authzPoliciesCmdUsage,
	Short: "Authorization management",
	Long:  "Create, get or delete an authorization policy",
}

var createAuthzPolicyCmd = &cobra.Command{
	Use:   createAuthzPolicyCmdUsage,
	Short: "Create an authorization policy",
	Long:  "Create an authorization policy",
	Run:   createAuthzPolicy,
}

var deleteAuthzPolicyCmd = &cobra.Command{
	Use:   deleteAuthzPolicyCmdUsage,
	Short: "Delete an authorization policy",
	Long:  "Delete a authorization policy",
	Run:   deleteAuthzPolicy,
}

var getAuthzPolicyCmd = &cobra.Command{
	Use:   getAuthzPolicyCmdUsage,
	Short: "Get an authorization policy",
	Long:  "Get an authorization policy",
	Run:   getAuthzPolicy,
}

func createAuthzPolicy(cmd *cobra.Command, args []string) {
	policyId, roleLabels, allowedOperations, owner, err := createAuthzPolicyCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	id, err := apiCreateAuthzPolicy(policyId, roleLabels, allowedOperations, owner)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Authorization policy created successfully")
	fmt.Printf("Id: %v\n", id)
}

func deleteAuthzPolicy(cmd *cobra.Command, args []string) {
	policyId, err := deleteAuthzPolicyCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = apiDeleteAuthzPolicy(policyId)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Authorization policy deleted successfully")
}

func getAuthzPolicy(cmd *cobra.Command, args []string) {
	policyId, err := getAuthzPolicyCheckUsage(args)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	pe, err := apiGetAuthzPolicy(policyId)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	s, err := util.JSONPrettyPrint(pe)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(s)
}

func createAuthzPolicyCheckUsage(args []string) (string, []string, []model.Operation, string, error) {
	if len(args) < 3 || len(args) > 4 {
		return "", []string{}, []model.Operation{}, "", fmt.Errorf("Usage: %v", createAuthzPolicyCmdUsage)
	}

	policyId := args[0]
	roleLabels := strings.Split(args[1], ",")

	allowedOperationsLabels := strings.Split(args[2], ",")
	allowedOperations := make([]model.Operation, 0, len(allowedOperationsLabels))
	for _, opLabel := range allowedOperationsLabels {
		if !model.IsValidOpLabel(opLabel) {
			return "", []string{}, []model.Operation{}, "", fmt.Errorf(
				"\"%v\" is not a valid operation label. Use a combination of %v, separated by \",\".",
				opLabel, model.ValidOpLabels())
		}
		allowedOperations = append(allowedOperations, model.Operation{Label: opLabel})
	}

	owner := ""
	if len(args) == 4 {
		owner = args[3]
	}

	return policyId, roleLabels, allowedOperations, owner, nil
}

func deleteAuthzPolicyCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", deleteAuthzPolicyCmdUsage)
	}

	policyId := args[0]

	return policyId, nil
}

func getAuthzPolicyCheckUsage(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("Usage: %v", getAuthzPolicyCmdUsage)
	}

	policyId := args[0]

	return policyId, nil
}

func apiCreateAuthzPolicy(policyId string, roleLabels []string, allowedOperations []model.Operation, owner string) (string, error) {
	if Token == "" {
		return "", fmt.Errorf("authn token is empty")
	}

	pe := &model.AuthorizationPolicyEntry{
		Id:                policyId,
		RoleLabels:        roleLabels,
		AllowedOperations: allowedOperations,
		Owner:             owner,
	}

	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(pe)
	if err != nil {
		return "", err
	}

	authzPoliciesUrl := fmt.Sprintf("%v/authz/policies", Url)
	req, err := http.NewRequest("POST", authzPoliciesUrl, body)
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

func apiDeleteAuthzPolicy(policyId string) error {
	if Token == "" {
		return fmt.Errorf("authn token is empty")
	}

	deleteUrl := fmt.Sprintf("%v/authz/policies/%v", Url, policyId)
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

func apiGetAuthzPolicy(policyId string) (*model.AuthorizationPolicyEntry, error) {
	if Token == "" {
		return nil, fmt.Errorf("authn token is empty")
	}

	getUrl := fmt.Sprintf("%v/authz/policies/%v", Url, policyId)
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

	var authzPolicyEntry model.AuthorizationPolicyEntry
	if err = json.NewDecoder(resp.Body).Decode(&authzPolicyEntry); err != nil {
		return nil, err
	}

	return &authzPolicyEntry, nil
}
