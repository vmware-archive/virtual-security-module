// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"time"
)

type UserEntry struct {
	Username     string   `json:"username"`
	Credentials  []byte   `json:"credentials"`
	RoleEntryIds []string `json:"roleEntryIds"`
}

type RoleEntry struct {
	Id           string   `json:"id"`
	Label        string   `json:"label"`
	UserEntryIds []string `json:"userEntryIds"`
}

type SecretEntry struct {
	Id                     string    `json:"id"`
	SecretData             []byte    `json:"secretData"`
	OwnerEntryId           string    `json:"ownerEntryId"`
	NamespaceEntryId       string    `json:"namespaceEntryId"`
	ExpirationTime         time.Time `json:"expirationTime"`
	AuthorizationPolicyIds []string  `json:"authorizationPolicyIds"`
}

type NamespaceEntry struct {
	Id                     string   `json:"id"`
	PathElement            string   `json:"pathElement"`
	OwnerEntryId           string   `json:"ownerEntryId"`
	ParentNamespaceEntryId string   `json:"parentNamespaceId"`
	AuthorizationPolicyIds []string `json:"authorizationPolicyIds"`
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
