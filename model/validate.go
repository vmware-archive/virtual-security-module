// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"encoding/json"
	"github.com/vmware/virtual-security-module/util"
	"net/http"
	"reflect"
	"strings"
)

func (s *SecretEntry) Equal(t *SecretEntry) bool {
	if !reflect.DeepEqual(s.AuthorizationPolicyIds, t.AuthorizationPolicyIds) ||
		!s.ExpirationTime.Equal(t.ExpirationTime) ||
		!reflect.DeepEqual(s.Id, t.Id) ||
		!reflect.DeepEqual(s.OwnerEntryId, t.OwnerEntryId) ||
		!reflect.DeepEqual(s.SecretData, t.SecretData) {

		return false
	}

	return true
}

func ExtractAndValidateSecretEntry(req *http.Request) (*SecretEntry, error) {
	decoder := json.NewDecoder(req.Body)
	var secretEntry SecretEntry
	if err := decoder.Decode(&secretEntry); err != nil {
		return nil, util.ErrInputValidation
	}
	defer req.Body.Close()

	if secretEntry.Id == "" || len(secretEntry.SecretData) == 0 {
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
