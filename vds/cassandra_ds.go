// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"fmt"
	"path"
	"strings"

	"github.com/gocql/gocql"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/util"
	"log"
)

const (
	cassandraDSType      = "CassandraDataStore"
	cassandraVSMKeySpace = "vsm"
	cassandraVSMTable    = "vsm_entries"
)

func init() {
	if err := DataStoreRegistrar.Register(cassandraDSType, NewCassandraDS()); err != nil {
		panic(fmt.Sprintf("Failed to register data store type %v: %v", cassandraDSType, err))
	}
}

// An implementation of a datastore based on Apache Cassandra.
//
// The Cassandra cluster is expected to have a table (whose name is determined by the constant
// cassandraVSMTable) under a key space (whose name is determined by the constant cassandraVSMKeySpace)
// with a schema corresponding to (id: string, parentId: string, data: []byte, metaData: string);
//
// For example:
//
//	CREATE KEYSPACE vsm WITH replication = {'class': 'SimpleStrategy', 'replication_factor' : 1};
//	CREATE TABLE vsm.vsm_entries (id text PRIMARY KEY, parent_id text, data blob, meta_data text);
//
// The field parentId is needed to implement SearchChildEntries as Cassandra does not support regexp queries.
type CassandraDS struct {
	dbSession *gocql.Session
	location  string
}

func NewCassandraDS() *CassandraDS {
	return &CassandraDS{}
}

func (ds *CassandraDS) Init(cfg *config.DataStoreConfig) error {
	connectionString := cfg.ConnectionString
	if connectionString == "" {
		log.Printf("%s: connectionString is empty\n", cassandraDSType)
		return util.ErrBadConfig
	}

	hostsAndSettings := strings.Split(connectionString, ";")
	if len(hostsAndSettings) == 0 {
		return util.ErrBadConfig
	}

	hosts := strings.Split(hostsAndSettings[0], ",")
	if len(hosts) == 0 {
		log.Printf("%s: connectionString: host is missing\n", cassandraDSType)
		return util.ErrBadConfig
	}

	cluster := gocql.NewCluster(hosts...)
	cluster.Keyspace = cassandraVSMKeySpace
	cluster.CQLVersion = "3.0.0"

	for i := 1; i < len(hostsAndSettings); i++ {
		keyVal := strings.SplitN(hostsAndSettings[i], "=", 2)
		if len(keyVal) != 2 {
			log.Printf("%s: bad key-val %v\n", cassandraDSType, keyVal)
			return util.ErrBadConfig
		}

		key := keyVal[0]
		val := keyVal[1]

		switch strings.ToUpper(key) {
		case "CONSISTENCY":
			consistency, err := gocql.ParseConsistencyWrapper(val)
			if err != nil {
				log.Printf("%s: connectionString: unrecognized consistency %s: %s\n", cassandraDSType, consistency, err.Error())
				return util.ErrBadConfig
			}
			cluster.Consistency = consistency

		case "DATACENTER":
			cluster.HostFilter = gocql.DataCentreHostFilter(val)

		default:
			log.Printf("%s: connectionString: unrecognized key: %s\n", cassandraDSType, key)
			return util.ErrBadConfig
		}
	}

	session, err := cluster.CreateSession()
	if err != nil {
		return err
	}
	session.SetConsistency(cluster.Consistency)

	ds.dbSession = session
	ds.location = connectionString

	return nil
}

func (ds *CassandraDS) CompleteInit(cfg *config.DataStoreConfig) error {
	return nil
}

func (ds *CassandraDS) Initialized() bool {
	return ds.dbSession != nil
}

func (ds *CassandraDS) CreateEntry(entry *DataStoreEntry) error {
	query := ds.buildInsertStatement(entry)
	defer query.Release()

	query.SerialConsistency(gocql.LocalSerial)
	var id, parentId, metaData string
	var data []byte
	applied, err := query.ScanCAS(&id, &parentId, &data, &metaData)
	if err != nil {
		return translateCassandraError(err)
	}

	if !applied {
		return util.ErrAlreadyExists
	}

	return nil
}

func (ds *CassandraDS) ReadEntry(entryId string) (*DataStoreEntry, error) {
	query := ds.buildFindEntryQuery(entryId)
	defer query.Release()

	var data []byte
	var metaData string
	err := query.Scan(&data, &metaData)
	if err != nil {
		return nil, translateCassandraError(err)
	}

	return &DataStoreEntry{
		Id:       entryId,
		Data:     data,
		MetaData: metaData,
	}, nil
}

func (ds *CassandraDS) DeleteEntry(entryId string) error {
	query := ds.buildDeleteEntryQuery(entryId)
	defer query.Release()

	err := query.Exec()
	if err != nil {
		return translateCassandraError(err)
	}

	return nil
}

func (ds *CassandraDS) SearchChildEntries(parentEntryId string) ([]*DataStoreEntry, error) {
	query := ds.buildFindChildrenQuery(parentEntryId)
	defer query.Release()

	iter := query.Iter()
	dsEntries := make([]*DataStoreEntry, 0)
	for {
		var id string
		var data []byte
		var metaData string
		if !iter.Scan(&id, &data, &metaData) {
			break
		}

		dsEntry := &DataStoreEntry{
			Id:       id,
			Data:     data,
			MetaData: metaData,
		}
		dsEntries = append(dsEntries, dsEntry)
	}

	err := iter.Close()
	if err != nil {
		return []*DataStoreEntry{}, translateCassandraError(err)
	}

	return dsEntries, nil
}

func (ds *CassandraDS) Type() string {
	return cassandraDSType
}

func (ds *CassandraDS) Location() string {
	return ds.location
}

func (ds *CassandraDS) buildInsertStatement(entry *DataStoreEntry) *gocql.Query {
	parentId := getParentPath(entry.Id)
	queryStr := fmt.Sprintf("INSERT INTO %s (id, parent_id, data, meta_data) VALUES (?, ?, ?, ?) IF NOT EXISTS", cassandraVSMTable)
	return ds.dbSession.Query(queryStr, entry.Id, parentId, entry.Data, entry.MetaData)
}

func (ds *CassandraDS) buildFindEntryQuery(entryId string) *gocql.Query {
	queryStr := fmt.Sprintf("SELECT data, meta_data FROM %s WHERE id = ?", cassandraVSMTable)
	return ds.dbSession.Query(queryStr, entryId)
}

func (ds *CassandraDS) buildDeleteEntryQuery(entryId string) *gocql.Query {
	queryStr := fmt.Sprintf("DELETE FROM %s WHERE id = ?", cassandraVSMTable)
	return ds.dbSession.Query(queryStr, entryId)
}

func (ds *CassandraDS) buildFindChildrenQuery(parentEntryId string) *gocql.Query {
	queryStr := fmt.Sprintf("SELECT id, data, meta_data FROM %s WHERE parent_id = ? ALLOW FILTERING", cassandraVSMTable)
	return ds.dbSession.Query(queryStr, parentEntryId)
}

func getParentPath(dir string) string {
	if dir == "/" {
		return ""
	}

	return path.Dir(dir)
}

func translateCassandraError(cassandraError error) error {
	switch cassandraError {
	case gocql.ErrNotFound:
		return util.ErrNotFound
	default:
		return cassandraError
	}
}
