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

func (ds *MongoDBDS) WriteEntry(entry *DataStoreEntry) error {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	_, err := collection.Upsert(bson.M{"id": entry.Id}, entry)

	if err != nil {
		err = translateError(err)
	}

	return err
}

func (ds *MongoDBDS) ReadEntry(entryId string) (*DataStoreEntry, error) {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	dsEntry := DataStoreEntry{}
	err := collection.Find(bson.M{"id": entryId}).One(&dsEntry)

	if err != nil {
		err = translateError(err)
	}

	return &dsEntry, err
}

func (ds *MongoDBDS) DeleteEntry(entryId string) error {
	session, collection := ds.getSessionAndCollection()
	defer session.Close()

	err := collection.Remove(bson.M{"id": entryId})

	if err != nil {
		err = translateError(err)
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

	var dsEntries []*DataStoreEntry
	err := collection.Find(bson.M{"id": bson.M{"$regex": bson.RegEx{Pattern: pattern}}}).All(&dsEntries)

	if err != nil {
		err = translateError(err)
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

func translateError(mongoError error) error {
	switch mongoError {
	case mgo.ErrNotFound:
		return util.ErrNotFound
	default:
		return mongoError
	}
}
