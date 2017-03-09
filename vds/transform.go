// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"encoding/json"
	"time"

	"github.com/vmware/virtual-security-module/model"
)

type MetaData struct {
	OwnerEntryId string
	NamespaceEntryId string
	ExpirationTime time.Time
	AuthorizationPolicyIds []string
}

func SecretEntryToDataStoreEntry(secretEntry *model.SecretEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		OwnerEntryId: secretEntry.OwnerEntryId,
		NamespaceEntryId: secretEntry.NamespaceEntryId,
		ExpirationTime: secretEntry.ExpirationTime,
		AuthorizationPolicyIds: secretEntry.AuthorizationPolicyIds,
	}

	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, err
	}

	dataStoreEntry := &DataStoreEntry{
		Id: secretEntry.Id,
		Data: secretEntry.SecretData,
		MetaData: string(metaDataBytes),
	}

	return dataStoreEntry, nil
}

func DataStoreEntryToSecretEntry(dataStoreEntry *DataStoreEntry) (*model.SecretEntry, error) {
	var metaData MetaData

	if err := json.Unmarshal([]byte(dataStoreEntry.MetaData), &metaData); err != nil {
		return nil, err
	}

	secretEntry := &model.SecretEntry{
		Id: dataStoreEntry.Id,
		SecretData: dataStoreEntry.Data,
		OwnerEntryId: metaData.OwnerEntryId,
		NamespaceEntryId: metaData.NamespaceEntryId,
		ExpirationTime: metaData.ExpirationTime,
		AuthorizationPolicyIds: metaData.AuthorizationPolicyIds,
	}

	return secretEntry, nil
}

func UserEntryToDataStoreEntry(userEntry *model.UserEntry) (*DataStoreEntry, error) {
	metaData := &MetaData{
		OwnerEntryId: userEntry.Username,
		NamespaceEntryId: "", // TODO: replace with built-in "users" namspace id
	}

	metaDataBytes, err := json.Marshal(metaData)
	if err != nil {
		return nil, err
	}

	dataStoreEntry := &DataStoreEntry{
		Id: userEntry.Username,
		Data: []byte(userEntry.Credentials),
		MetaData: string(metaDataBytes),
	}

	return dataStoreEntry, nil
}

func DataStoreEntryToUserEntry(dataStoreEntry *DataStoreEntry) (*model.UserEntry, error) {
	var metaData MetaData
	
	if err := json.Unmarshal([]byte(dataStoreEntry.MetaData), &metaData); err != nil {
		return nil, err
	}

	userEntry := &model.UserEntry{
		Username: dataStoreEntry.Id,
		Credentials: dataStoreEntry.Data,
	}

	return userEntry, nil
}