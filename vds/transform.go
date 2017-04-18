// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"encoding/json"
	"path"
	"strings"
	"time"

	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

const (
	PoliciesDirname = "policies"

	secretsPathPrefix = "/secrets/"
	usersPathPrefix   = "/users/"

	secretEntryType              = "secret"
	userEntryType                = "user"
	namespaceEntryType           = "namespace"
	authorizationPolicyEntryType = "authzPolicy"
)

type RoleMetaData struct {
	Scope string
	Label string
}

type OperationMetaData struct {
	Label string
}

type MetaData struct {
	EntryType         string
	SecretType        string
	Owner             string
	ExpirationTime    time.Time
	Roles             []RoleMetaData
	AllowedOperations []OperationMetaData
}

func SecretEntryToDataStoreEntry(secretEntry *model.SecretEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		EntryType:      secretEntryType,
		SecretType:     secretEntry.Type,
		Owner:          secretEntry.Owner,
		ExpirationTime: secretEntry.ExpirationTime,
	}

	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, util.ErrInternal
	}

	dataStoreEntry := &DataStoreEntry{
		Id:       SecretIdToPath(secretEntry.Id),
		Data:     secretEntry.SecretData,
		MetaData: string(metaDataBytes),
	}

	return dataStoreEntry, nil
}

func DataStoreEntryToSecretEntry(dataStoreEntry *DataStoreEntry) (*model.SecretEntry, error) {
	var metaData MetaData

	if err := json.Unmarshal([]byte(dataStoreEntry.MetaData), &metaData); err != nil {
		return nil, util.ErrInternal
	}

	if metaData.EntryType != secretEntryType {
		return nil, util.ErrInternal
	}

	secretEntry := &model.SecretEntry{
		Id:             SecretPathToId(dataStoreEntry.Id),
		Type:           metaData.SecretType,
		SecretData:     dataStoreEntry.Data,
		Owner:          metaData.Owner,
		ExpirationTime: metaData.ExpirationTime,
	}

	return secretEntry, nil
}

func UserEntryToDataStoreEntry(userEntry *model.UserEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		EntryType: userEntryType,
		Owner:     userEntry.Username,
		Roles:     rolesToMetaData(userEntry.Roles),
	}

	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, util.ErrInternal
	}

	dataStoreEntry := &DataStoreEntry{
		Id:       UsernameToPath(userEntry.Username),
		Data:     []byte(userEntry.Credentials),
		MetaData: string(metaDataBytes),
	}

	return dataStoreEntry, nil
}

func DataStoreEntryToUserEntry(dataStoreEntry *DataStoreEntry) (*model.UserEntry, error) {
	var metaData MetaData

	if err := json.Unmarshal([]byte(dataStoreEntry.MetaData), &metaData); err != nil {
		return nil, util.ErrInternal
	}

	if metaData.EntryType != userEntryType {
		return nil, util.ErrInternal
	}

	userEntry := &model.UserEntry{
		Username:    UserpathToName(dataStoreEntry.Id),
		Credentials: dataStoreEntry.Data,
		Roles:       rolesFromMetaData(metaData.Roles),
	}

	return userEntry, nil
}

func NamespaceEntryToDataStoreEntry(namespaceEntry *model.NamespaceEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		EntryType: namespaceEntryType,
		Owner:     namespaceEntry.Owner,
		Roles:     roleLabelsToMetaData(namespaceEntry.RoleLabels),
	}
	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, util.ErrInternal
	}

	dataStoreEntry := &DataStoreEntry{
		Id:       namespaceEntry.Path,
		Data:     []byte{},
		MetaData: string(metaDataBytes),
	}

	return dataStoreEntry, nil
}

func DataStoreEntryToNamespaceEntry(dataStoreEntry *DataStoreEntry) (*model.NamespaceEntry, error) {
	var metaData MetaData
	if err := json.Unmarshal([]byte(dataStoreEntry.MetaData), &metaData); err != nil {
		return nil, util.ErrInternal
	}

	if metaData.EntryType != namespaceEntryType {
		return nil, util.ErrInternal
	}

	namespaceEntry := &model.NamespaceEntry{
		Path:       dataStoreEntry.Id,
		Owner:      metaData.Owner,
		RoleLabels: roleLabelsFromMetaData(metaData.Roles),
	}

	return namespaceEntry, nil
}

func AuthorizationPolicyEntryToDataStoreEntry(policyEntry *model.AuthorizationPolicyEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		EntryType:         authorizationPolicyEntryType,
		Owner:             policyEntry.Owner,
		Roles:             roleLabelsToMetaData(policyEntry.RoleLabels),
		AllowedOperations: operationsToMetaData(policyEntry.AllowedOperations),
	}
	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, util.ErrInternal
	}

	dataStoreEntry := &DataStoreEntry{
		Id:       AuthorizationPolicyIdToPath(policyEntry.Id),
		Data:     []byte{},
		MetaData: string(metaDataBytes),
	}

	return dataStoreEntry, nil
}

func DataStoreEntryToAuthorizationPolicyEntry(dataStoreEntry *DataStoreEntry) (*model.AuthorizationPolicyEntry, error) {
	var metaData MetaData
	if err := json.Unmarshal([]byte(dataStoreEntry.MetaData), &metaData); err != nil {
		return nil, util.ErrInternal
	}

	if metaData.EntryType != authorizationPolicyEntryType {
		return nil, util.ErrInternal
	}

	policyEntry := &model.AuthorizationPolicyEntry{
		Id:                AuthorizationPolicyPathToId(dataStoreEntry.Id),
		Owner:             metaData.Owner,
		RoleLabels:        roleLabelsFromMetaData(metaData.Roles),
		AllowedOperations: operationsFromMetaData(metaData.AllowedOperations),
	}

	return policyEntry, nil
}

func DataStoreEntriesToPaths(dataStoreEntries []*DataStoreEntry) []string {
	paths := make([]string, 0, len(dataStoreEntries))

	for _, dataStoreEntry := range dataStoreEntries {
		paths = append(paths, dataStoreEntry.Id)
	}

	return paths
}

func SecretIdToPath(secretId string) string {
	return secretsPathPrefix + secretId
}

func SecretPathToId(secretPath string) string {
	return strings.TrimPrefix(secretPath, secretsPathPrefix)
}

func UsernameToPath(username string) string {
	return usersPathPrefix + username
}

func UserpathToName(userpath string) string {
	return strings.TrimPrefix(userpath, usersPathPrefix)
}

func AuthorizationPolicyIdToPath(policyId string) string {
	dir, file := path.Split(policyId)
	return path.Join("/", dir, PoliciesDirname, file)
}

func AuthorizationPolicyPathToId(policyPath string) string {
	policiesDir, file := path.Split(policyPath)
	dir := path.Dir(strings.TrimSuffix(policiesDir, "/"))
	return strings.TrimPrefix(path.Join(dir, file), "/")
}

func rolesToMetaData(roles []model.RoleEntry) []RoleMetaData {
	rolesMetaData := make([]RoleMetaData, 0, len(roles))

	for _, role := range roles {
		rolesMetaData = append(rolesMetaData, roleToMetaData(role))
	}

	return rolesMetaData
}

func rolesFromMetaData(rolesMetaData []RoleMetaData) []model.RoleEntry {
	roles := make([]model.RoleEntry, 0, len(rolesMetaData))

	for _, roleMetaData := range rolesMetaData {
		roles = append(roles, roleFromMetaData(roleMetaData))
	}

	return roles
}

func operationsToMetaData(operations []model.Operation) []OperationMetaData {
	operationsMetaData := make([]OperationMetaData, 0, len(operations))

	for _, op := range operations {
		operationsMetaData = append(operationsMetaData, operationToMetaData(op))
	}

	return operationsMetaData
}

func operationsFromMetaData(operationsMetaData []OperationMetaData) []model.Operation {
	operations := make([]model.Operation, 0, len(operationsMetaData))

	for _, operationMetaData := range operationsMetaData {
		operations = append(operations, operationFromMetaData(operationMetaData))
	}

	return operations
}

func roleLabelsToMetaData(roleLabels []string) []RoleMetaData {
	rolesMetaData := make([]RoleMetaData, 0, len(roleLabels))

	for _, roleLabel := range roleLabels {
		rolesMetaData = append(rolesMetaData, roleLabelToMetaData(roleLabel))
	}

	return rolesMetaData
}

func roleLabelsFromMetaData(rolesMetaData []RoleMetaData) []string {
	roleLabels := make([]string, 0, len(rolesMetaData))

	for _, roleMetaData := range rolesMetaData {
		roleLabels = append(roleLabels, roleLabelFromMetaData(roleMetaData))
	}

	return roleLabels
}

func roleToMetaData(role model.RoleEntry) RoleMetaData {
	return RoleMetaData{
		Scope: role.Scope,
		Label: role.Label,
	}
}

func roleFromMetaData(roleMetaData RoleMetaData) model.RoleEntry {
	return model.RoleEntry{
		Scope: roleMetaData.Scope,
		Label: roleMetaData.Label,
	}
}

func operationToMetaData(operation model.Operation) OperationMetaData {
	return OperationMetaData{
		Label: operation.Label,
	}
}

func operationFromMetaData(operationMetaData OperationMetaData) model.Operation {
	return model.Operation{
		Label: operationMetaData.Label,
	}
}

func roleLabelToMetaData(roleLabel string) RoleMetaData {
	return RoleMetaData{
		Scope: "",
		Label: roleLabel,
	}
}

func roleLabelFromMetaData(roleMetaData RoleMetaData) string {
	return roleMetaData.Label
}
