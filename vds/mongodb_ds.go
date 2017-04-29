// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"fmt"
	"strings"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/util"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	mongoDSType      = "MongoDBDataStore"
	dbCollectionName = "VSMEntries"
)

func init() {
	if err := DataStoreRegistrar.Register(mongoDSType, NewMongoDBDS()); err != nil {
		panic(fmt.Sprintf("Failed to register data store type %v: %v", mongoDSType, err))
	}
}

// An implementation of a datastore based on MongoDB.
type MongoDBDS struct {
	dbSession *mgo.Session
	location  string
}

func NewMongoDBDS() *MongoDBDS {
	return &MongoDBDS{}
}

func (ds *MongoDBDS) Init(cfg *config.Config) error {
	connectionString := cfg.DataStoreConfig.ConnectionString
	if connectionString == "" {
		return util.ErrBadConfig
	}

	session, err := mgo.Dial(connectionString)
	if err != nil {
		return err
	}

	ds.dbSession = session
	ds.location = connectionString

	return nil
}

func (ds *MongoDBDS) CompleteInit(*config.Config) error {
	return nil
}

func (ds *MongoDBDS) Initialized() bool {
	return ds.dbSession != nil
}

func (ds *MongoDBDS) CreateEntry(entry *DataStoreEntry) error {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	doc := translateToMongoDocument(entry)
	err := collection.Insert(doc)
	if err != nil {
		return translateError(err)
	}

	return nil
}

func (ds *MongoDBDS) ReadEntry(entryId string) (*DataStoreEntry, error) {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	doc := bson.M{}
	err := collection.Find(bson.M{"_id": entryId}).One(&doc)

	if err != nil {
		return nil, translateError(err)
	}

	dsEntry, err := translatefromMongoDocument(&doc)
	if err != nil {
		return nil, err
	}

	return dsEntry, nil
}

func (ds *MongoDBDS) DeleteEntry(entryId string) error {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	err := collection.Remove(bson.M{"_id": entryId})
	if err != nil {
		return translateError(err)
	}

	return err
}

func (ds *MongoDBDS) SearchChildEntries(parentEntryId string) ([]*DataStoreEntry, error) {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	suffix := "([^/]+)"
	if !strings.HasSuffix(parentEntryId, "/") {
		suffix = "/" + suffix
	}
	pattern := "^" + parentEntryId + suffix + "$"

	var docs []*bson.M
	err := collection.Find(bson.M{"_id": bson.M{"$regex": bson.RegEx{Pattern: pattern}}}).All(&docs)

	if err != nil {
		return []*DataStoreEntry{}, translateError(err)
	}

	dsEntries := make([]*DataStoreEntry, 0, len(docs))
	for _, doc := range docs {
		dsEntry, err := translatefromMongoDocument(doc)
		if err != nil {
			return []*DataStoreEntry{}, err
		}

		dsEntries = append(dsEntries, dsEntry)
	}

	return dsEntries, err
}

func (ds *MongoDBDS) Type() string {
	return mongoDSType
}

func (ds *MongoDBDS) Location() string {
	return ds.location
}

func (ds *MongoDBDS) getSessionAndCollection() (*mgo.Session, *mgo.Collection) {
	session := ds.dbSession.Copy()
	db := session.DB("")
	collection := db.C(dbCollectionName)

	return session, collection
}

func translateToMongoDocument(dsEntry *DataStoreEntry) *bson.M {
	return &bson.M{
		"_id":      dsEntry.Id,
		"data":     dsEntry.Data,
		"metaData": dsEntry.MetaData,
	}
}

func translatefromMongoDocument(mongoDoc *bson.M) (*DataStoreEntry, error) {
	doc := map[string]interface{}(*mongoDoc)

	id, ok := doc["_id"].(string)
	if !ok {
		return nil, util.ErrInternal
	}

	data, ok := doc["data"].([]byte)
	if !ok {
		return nil, util.ErrInternal
	}

	metaData, ok := doc["metaData"].(string)
	if !ok {
		return nil, util.ErrInternal
	}

	return &DataStoreEntry{
		Id:       id,
		Data:     data,
		MetaData: metaData,
	}, nil
}

func translateError(mongoError error) error {
	switch mongoError {
	case mgo.ErrNotFound:
		return util.ErrNotFound
	default:
		if strings.Contains(mongoError.Error(), "E11000 duplicate key error") {
			return util.ErrAlreadyExists
		}

		return util.ErrInternal
	}
}
