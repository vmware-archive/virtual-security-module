// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authz

import (
	"path"
	"strings"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

type AuthorizationManager interface {
	Allowed(username string, op model.Operation, namespacePath string) error
}

type AuthzManager struct {
	dataStore vds.DataStoreAdapter
	keyStore  vks.KeyStoreAdapter
}

func New() *AuthzManager {
	return &AuthzManager{}
}

func (authzManager *AuthzManager) Type() string {
	return "AuthzManager"
}

func (authzManager *AuthzManager) Init(moduleInitContext *context.ModuleInitContext) error {
	authzManager.dataStore = moduleInitContext.DataStore
	authzManager.keyStore = moduleInitContext.KeyStore

	return nil
}

func (authzManager *AuthzManager) Close() error {
	return nil
}

func (authzManager *AuthzManager) CreatePolicy(policyEntry *model.AuthorizationPolicyEntry) (string, error) {
	policyPath := vds.AuthorizationPolicyIdToPath(policyEntry.Id)

	if _, err := authzManager.dataStore.ReadEntry(policyPath); err == nil {
		return "", util.ErrAlreadyExists
	}

	// create policies namespace if it doesn't exist
	policiesDir := path.Dir(policyPath)
	policiesDsEntry, err := authzManager.dataStore.ReadEntry(policiesDir)
	if err != nil {
		// policies dir doesn't exist - create it
		namespaceEntry := &model.NamespaceEntry{
			Path:       policiesDir,
			Owner:      policyEntry.Owner,
			RoleLabels: []string{},
			ChildPaths: []string{},
		}
		dataStoreEntry, err := vds.NamespaceEntryToDataStoreEntry(namespaceEntry)
		if err != nil {
			return "", err
		}
		if err := authzManager.dataStore.WriteEntry(dataStoreEntry); err != nil {
			return "", err
		}
	} else {
		// policies dir already exists - verify it's a namespace
		if !vds.IsNamespaceEntry(policiesDsEntry) {
			return "", util.ErrInputValidation
		}
	}

	dataStoreEntry, err := vds.AuthorizationPolicyEntryToDataStoreEntry(policyEntry)
	if err != nil {
		return "", err
	}
	if err := authzManager.dataStore.WriteEntry(dataStoreEntry); err != nil {
		return "", err
	}

	return policyEntry.Id, nil
}

func (authzManager *AuthzManager) GetPolicy(policyId string) (*model.AuthorizationPolicyEntry, error) {
	policyPath := vds.AuthorizationPolicyIdToPath(policyId)

	dataStoreEntry, err := authzManager.dataStore.ReadEntry(policyPath)
	if err != nil {
		return nil, err
	}

	policyEntry, err := vds.DataStoreEntryToAuthorizationPolicyEntry(dataStoreEntry)
	if err != nil {
		return nil, err
	}

	return policyEntry, nil
}

func (authzManager *AuthzManager) DeletePolicy(policyId string) error {
	policyPath := vds.AuthorizationPolicyIdToPath(policyId)

	dsEntry, err := authzManager.dataStore.ReadEntry(policyPath)
	if err != nil {
		return err
	}

	if !vds.IsAuthorizationPolicyEntry(dsEntry) {
		return util.ErrInputValidation
	}

	if err := authzManager.dataStore.DeleteEntry(policyPath); err != nil {
		return err
	}

	return nil
}

func (authzManager *AuthzManager) Allowed(username string, op model.Operation, namespacePath string) error {
	if username == "root" {
		dsEntry, err := authzManager.dataStore.ReadEntry(namespacePath)
		if err != nil {
			return err
		}

		if !vds.IsNamespaceEntry(dsEntry) {
			return util.ErrInputValidation
		}

		return nil
	}

	dsEntry, err := authzManager.dataStore.ReadEntry(vds.UsernameToPath(username))
	if err != nil {
		return util.ErrUnauthorized
	}

	userEntry, err := vds.DataStoreEntryToUserEntry(dsEntry)
	if err != nil {
		return util.ErrUnauthorized
	}

	return authzManager.allowed(userEntry, op, namespacePath)
}

func (authzManager *AuthzManager) allowed(ue *model.UserEntry, op model.Operation, namespacePath string) error {
	dsEntry, err := authzManager.dataStore.ReadEntry(namespacePath)
	if err != nil {
		return err
	}

	nsEntry, err := vds.DataStoreEntryToNamespaceEntry(dsEntry)
	if err != nil {
		return util.ErrInputValidation
	}

	// find closest policy/policies on path from namespace to root
	policiesPath := path.Join(nsEntry.Path, vds.PoliciesDirname)
	policiesDsEntry, err := authzManager.dataStore.ReadEntry(policiesPath)
	if err != nil {
		return err
	}

	policiesNsEntry, err := vds.DataStoreEntryToNamespaceEntry(policiesDsEntry)
	if err != nil {
		return err
	}

	if len(policiesNsEntry.ChildPaths) == 0 {
		if namespacePath == "/" {
			return util.ErrNotFound
		} else {
			// search in parent path, recursively
			parentPath := path.Dir(nsEntry.Path)
			return authzManager.allowed(ue, op, parentPath)
		}
	}

	policies := make([]*model.AuthorizationPolicyEntry, len(policiesNsEntry.ChildPaths))
	for _, policyPath := range policiesNsEntry.ChildPaths {
		policyDsEntry, err := authzManager.dataStore.ReadEntry(policyPath)
		if err != nil {
			return err
		}

		policy, err := vds.DataStoreEntryToAuthorizationPolicyEntry(policyDsEntry)
		if err != nil {
			return err
		}

		policies = append(policies, policy)
	}

	// we have found one or more policies - determine if op is allowed by at least one policy.
	// we need to determine user's roles at this scope (including roles inherited from parent scopes), if any
	for _, roleEntry := range ue.Roles {
		if strings.HasPrefix(namespacePath, roleEntry.Scope) {
			// found a relevant user's role - check of one of the policies grants access
			for _, policy := range policies {
				if policyPermitsRoleLabelAndOp(policy, roleEntry.Label, op) {
					return nil
				}
			}
		}
	}

	return util.ErrUnauthorized
}

func policyPermitsRoleLabelAndOp(policy *model.AuthorizationPolicyEntry, roleLabel string, op model.Operation) bool {
	policyPermitsRoleLabel := false
	for _, policyRoleLabel := range policy.RoleLabels {
		if policyRoleLabel == roleLabel {
			policyPermitsRoleLabel = true
			break
		}
	}

	if !policyPermitsRoleLabel {
		return false
	}

	for _, allowedOperation := range policy.AllowedOperations {
		if allowedOperation.Label == op.Label {
			return true
		}
	}

	return false
}
