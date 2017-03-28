// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"time"
)

type UserEntry struct {
	Username    string `json:"username"`
	Credentials []byte `json:"credentials"`
}

type RoleEntry struct {
	Scope     string   `json:"scope"`
	Label     string   `json:"label"`
	Usernames []string `json:"usernames"`
}

type SecretEntry struct {
	Id                     string    `json:"id"`
	SecretData             []byte    `json:"secretData"`
	OwnerEntryId           string    `json:"ownerEntryId"`
	ExpirationTime         time.Time `json:"expirationTime"`
	AuthorizationPolicyIds []string  `json:"authorizationPolicyIds"`
}

type NamespaceEntry struct {
	Path                   string   `json:"path"`
	OwnerEntryId           string   `json:"ownerEntryId"`
	AuthorizationPolicyIds []string `json:"authorizationPolicyIds"`
	ChildPaths             []string `json:"childPaths"`
}

const (
	OpCreate = "C"
	OpWrite  = "W"
	OpUpdate = "U"
	OpDelete = "D"
)

type Operation struct {
	Label string `json:"label"`
}

type AuthorizationPolicyEntry struct {
	Id                string      `json:"id"`
	Name              string      `json:"name"`
	RoleEntryIds      []string    `json:"roleEntryIds"`
	AllowedOperations []Operation `json:"allowedOperations"`
	OwnerEntryId      string      `json:"ownerEntryId"`
}
