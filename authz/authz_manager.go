// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authz

import (
	"github.com/vmware/virtual-security-module/model"
)

type AuthorizationManager interface {
	AllowedOnSecret(userId string, op model.Operation, entry *model.SecretEntry) (bool, error)
	AllowedOnNamespace(userId string, op model.Operation, entry *model.NamespaceEntry) (bool, error)
	AllowedOnUser(userId string, op model.Operation, entry *model.UserEntry) (bool, error)
	AllowedOnRole(userId string, op model.Operation, entry *model.RoleEntry) (bool, error)
	AllowedOnPolicy(userId string, op model.Operation, entry *model.AuthorizationPolicyEntry) (bool, error)
}
