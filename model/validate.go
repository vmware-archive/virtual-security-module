// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"encoding/json"
	"github.com/vmware/virtual-security-module/util"
	"net/http"
	"strings"
)

func ExtractAndValidateSecretEntry(req *http.Request) (*SecretEntry, error) {
	decoder := json.NewDecoder(req.Body)
	var secretEntry SecretEntry
	if err := decoder.Decode(&secretEntry); err != nil {
		return nil, util.ErrInputValidation
	}
	defer req.Body.Close()

	if secretEntry.Id == "" || secretEntry.Type == "" {
		return nil, util.ErrInputValidation
	}

	return &secretEntry, nil
}

func ExtractAndValidateUserEntry(req *http.Request) (*UserEntry, error) {
	decoder := json.NewDecoder(req.Body)
	var userEntry UserEntry
	if err := decoder.Decode(&userEntry); err != nil {
		return nil, util.ErrInputValidation
	}
	defer req.Body.Close()

	if len(userEntry.Username) == 0 || len(userEntry.Credentials) == 0 {
		return nil, util.ErrInputValidation
	}

	return &userEntry, nil
}

func ExtractAndValidateLoginRequest(req *http.Request) (*LoginRequest, error) {
	decoder := json.NewDecoder(req.Body)
	var loginRequest LoginRequest
	if err := decoder.Decode(&loginRequest); err != nil {
		return nil, util.ErrInputValidation
	}
	defer req.Body.Close()

	if len(loginRequest.Username) == 0 {
		return nil, util.ErrInputValidation
	}

	return &loginRequest, nil
}

func ExtractAndValidateNamespaceEntry(req *http.Request) (*NamespaceEntry, error) {
	decoder := json.NewDecoder(req.Body)
	var namespaceEntry NamespaceEntry
	if err := decoder.Decode(&namespaceEntry); err != nil {
		return nil, util.ErrInputValidation
	}
	defer req.Body.Close()

	reqNamespacePath := strings.TrimPrefix(req.URL.Path, "/namespaces")
	if !strings.HasPrefix(namespaceEntry.Path, reqNamespacePath) {
		return nil, util.ErrInputValidation
	}

	if len(namespaceEntry.ChildPaths) != 0 {
		return nil, util.ErrInputValidation
	}

	return &namespaceEntry, nil
}

func ExtractAndValidateAuthorizationPolicyEntry(req *http.Request) (*AuthorizationPolicyEntry, error) {
	decoder := json.NewDecoder(req.Body)
	var authzPolicyEntry AuthorizationPolicyEntry
	if err := decoder.Decode(&authzPolicyEntry); err != nil {
		return nil, util.ErrInputValidation
	}
	defer req.Body.Close()

	if authzPolicyEntry.Id == "" {
		return nil, util.ErrInputValidation
	}

	return &authzPolicyEntry, nil
}

func IsValidOpLabel(label string) bool {
	return label == OpCreate ||
		label == OpRead ||
		label == OpUpdate ||
		label == OpDelete
}

func ValidOpLabels() []string {
	return []string{OpCreate, OpRead, OpUpdate, OpDelete}
}
