// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"fmt"
	"log"
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

func (ds *MongoDBDS) Init(cfg *config.DataStoreConfig) error {
	connectionString := cfg.ConnectionString
	if connectionString == "" {
		return util.ErrBadConfig
	}

	connectStrAndSettings := strings.Split(connectionString, ";")
	if len(connectStrAndSettings) == 0 {
		return util.ErrBadConfig
	}

	connectStr := connectStrAndSettings[0]
	session, err := mgo.Dial(connectStr)
	if err != nil {
		return err
	}

	for i := 1; i < len(connectStrAndSettings); i++ {
		keyVal := strings.SplitN(connectStrAndSettings[i], "=", 2)
		if len(keyVal) != 2 {
			log.Printf("%s: bad key-val %v\n", mongoDSType, keyVal)
			return util.ErrBadConfig
		}

		key := keyVal[0]
		val := keyVal[1]

		switch strings.ToUpper(key) {
		case "WRITE_CONCERN":
			safe := session.Safe()
			safe.WMode = val
			session.SetSafe(safe)

		default:
			log.Printf("%s: connectionString: unrecognized key: %s\n", mongoDSType, key)
			return util.ErrBadConfig
		}
	}

	ds.dbSession = session
	ds.location = connectStr

	return nil
}

func (ds *MongoDBDS) CompleteInit(cfg *config.DataStoreConfig) error {
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
		return translateMongoError(err)
	}

	return nil
}

func (ds *MongoDBDS) ReadEntry(entryId string) (*DataStoreEntry, error) {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	doc := bson.M{}
	err := collection.Find(bson.M{"_id": entryId}).One(&doc)

	if err != nil {
		return nil, translateMongoError(err)
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
		return translateMongoError(err)
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
		return []*DataStoreEntry{}, translateMongoError(err)
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

func translateMongoError(mongoError error) error {
	switch mongoError {
	case mgo.ErrNotFound:
		return util.ErrNotFound
	default:
		if strings.Contains(mongoError.Error(), "E11000 duplicate key error") {
			return util.ErrAlreadyExists
		}

		return mongoError
	}
}
