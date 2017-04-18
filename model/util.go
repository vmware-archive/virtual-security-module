// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"bytes"
)

func SecretsEqual(s, t *SecretEntry) bool {
	if s == nil || t == nil {
		return s == t
	}

	if !s.ExpirationTime.Equal(t.ExpirationTime) ||
		!(s.Id == t.Id) ||
		!(s.Type == t.Type) ||
		!(s.Owner == t.Owner) ||
		!bytes.Equal(s.SecretData, t.SecretData) {

		return false
	}

	return true
}

func NewUserEntry(ue *UserEntry) *UserEntry {
	return &UserEntry{
		Username:    ue.Username,
		Credentials: ue.Credentials,
		Roles:       ue.Roles,
	}
}

func NewRoleEntry(re *RoleEntry) *RoleEntry {
	return &RoleEntry{
		Scope: re.Scope,
		Label: re.Label,
	}
}

func NewSecretEntry(se *SecretEntry) *SecretEntry {
	return &SecretEntry{
		Id:             se.Id,
		Type:           se.Type,
		SecretData:     se.SecretData,
		Owner:          se.Owner,
		ExpirationTime: se.ExpirationTime,
	}
}

func NewNamespaceEntry(ne *NamespaceEntry) *NamespaceEntry {
	return &NamespaceEntry{
		Path:       ne.Path,
		Owner:      ne.Owner,
		ChildPaths: ne.ChildPaths,
	}
}

func NewAuthorizationPolicyEntry(ape *AuthorizationPolicyEntry) *AuthorizationPolicyEntry {
	return &AuthorizationPolicyEntry{
		Id:                ape.Id,
		RoleLabels:        ape.RoleLabels,
		AllowedOperations: ape.AllowedOperations,
		Owner:             ape.Owner,
	}
}
