// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"time"
)

type UserEntry struct {
	Id string
	Username string
	RoleEntryIds []string
}

type RoleEntry struct {
	Id string
	Label string
	UserEntryIds []string
}

type SecretEntry struct {
	Id string
	SecretData []byte
	OwnerEntryId string
	NamespaceEntryId string
	ExpirationTime time.Time
	AuthorizationPolicyIds []string
}

type NamespaceEntry struct {
	Id string
	PathElement string
	OwnerEntryId string
	ParentNamespaceEntryId string
	AuthorizationPolicyIds []string
}

const (
	OpCreate = "C"
	OpWrite = "W"
	OpUpdate = "U"
	OpDelete = "D"
)
type Operation struct {
	label string
}

type AuthorizationPolicyEntry struct {
	Id string
	Name string
	RoleEntryIds []string
	AllowedOperations []Operation
	OwnerEntryId string
}