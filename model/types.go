// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"time"
)

type UserEntry struct {
	Username    string      `json:"username"`
	Credentials []byte      `json:"credentials"`
	Roles       []RoleEntry `json:"roles"`
}

type RoleEntry struct {
	Scope string `json:"scope"`
	Label string `json:"label"`
}

type SecretEntry struct {
	Id             string    `json:"id"`
	SecretData     []byte    `json:"secretData"`
	Owner          string    `json:"owner"`
	ExpirationTime time.Time `json:"expirationTime"`
}

type NamespaceEntry struct {
	Path       string   `json:"path"`
	Owner      string   `json:"owner"`
	RoleLabels []string `json:"roleLabels"`
	ChildPaths []string `json:"childPaths"`
}

const (
	OpCreate = "C"
	OpRead   = "R"
	OpUpdate = "U"
	OpDelete = "D"
)

type Operation struct {
	Label string `json:"label"`
}

type AuthorizationPolicyEntry struct {
	Id                string      `json:"id"`
	RoleLabels        []string    `json:"roleLabels"`
	AllowedOperations []Operation `json:"allowedOperations"`
	Owner             string      `json:"owner"`
}
