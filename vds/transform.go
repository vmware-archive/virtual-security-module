// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

const (
	secretsPathPrefix = "/secrets/"
	usersPathPrefix   = "/users/"
)

type MetaData struct {
	OwnerEntryId           string
	NamespaceEntryId       string
	ExpirationTime         time.Time
	AuthorizationPolicyIds []string
}

func SecretEntryToDataStoreEntry(secretEntry *model.SecretEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		OwnerEntryId:           secretEntry.OwnerEntryId,
		ExpirationTime:         secretEntry.ExpirationTime,
		AuthorizationPolicyIds: secretEntry.AuthorizationPolicyIds,
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

	secretEntry := &model.SecretEntry{
		Id:                     SecretPathToId(dataStoreEntry.Id),
		SecretData:             dataStoreEntry.Data,
		OwnerEntryId:           metaData.OwnerEntryId,
		ExpirationTime:         metaData.ExpirationTime,
		AuthorizationPolicyIds: metaData.AuthorizationPolicyIds,
	}

	return secretEntry, nil
}

func UserEntryToDataStoreEntry(userEntry *model.UserEntry) (*DataStoreEntry, error) {
	userpath := UsernameToPath(userEntry.Username)

	metaData := &MetaData{
		OwnerEntryId:     userEntry.Username,
		NamespaceEntryId: userpath,
	}

	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, util.ErrInternal
	}

	dataStoreEntry := &DataStoreEntry{
		Id:       userpath,
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

	userEntry := &model.UserEntry{
		Username:    UserpathToName(dataStoreEntry.Id),
		Credentials: dataStoreEntry.Data,
	}

	return userEntry, nil
}

func NamespaceEntryToDataStoreEntry(namespaceEntry *model.NamespaceEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		OwnerEntryId: namespaceEntry.OwnerEntryId,
	}
	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, util.ErrInternal
	}

	data, err := json.Marshal(namespaceEntry.AuthorizationPolicyIds)
	if err != nil {
		return nil, util.ErrInternal
	}

	dataStoreEntry := &DataStoreEntry{
		Id:       namespaceEntry.Path,
		Data:     data,
		MetaData: string(metaDataBytes),
	}

	return dataStoreEntry, nil
}

func DataStoreEntryToNamespaceEntry(dataStoreEntry *DataStoreEntry) (*model.NamespaceEntry, error) {
	var metaData MetaData
	if err := json.Unmarshal([]byte(dataStoreEntry.MetaData), &metaData); err != nil {
		return nil, util.ErrInternal
	}

	var authorizationPolicyIds []string
	if err := json.Unmarshal(dataStoreEntry.Data, &authorizationPolicyIds); err != nil {
		return nil, util.ErrInternal
	}

	namespaceEntry := &model.NamespaceEntry{
		Path:                   dataStoreEntry.Id,
		OwnerEntryId:           metaData.OwnerEntryId,
		AuthorizationPolicyIds: authorizationPolicyIds,
	}

	return namespaceEntry, nil
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
