// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/util"
)

const (
	boltKSType = "BoltKeyStore"
	vsmBucket  = "VSM"
)

func init() {
	if err := KeyStoreRegistrar.Register(boltKSType, NewBoltKS()); err != nil {
		panic(fmt.Sprintf("Failed to register key store type %v: %v", boltKSType, err))
	}
}

// An implementation of a keystore using Bolt (https://github.com/boltdb/bolt)
type BoltKS struct {
	db       *bolt.DB
	location string
}

func NewBoltKS() *BoltKS {
	return &BoltKS{}
}

func (ks *BoltKS) Init(cfg *config.KeyStoreConfig) error {
	connectionString := cfg.ConnectionString
	if connectionString == "" {
		return util.ErrBadConfig
	}

	db, err := bolt.Open(connectionString, 0600, nil)
	if err != nil {
		return err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(vsmBucket))
		if err != nil {
			return translateBoltError(err)
		}
		return nil
	})
	if err != nil {
		return translateBoltError(err)
	}

	ks.db = db
	ks.location = connectionString

	return nil
}

func (ks *BoltKS) CompleteInit(*config.KeyStoreConfig) error {
	return nil
}

func (ks *BoltKS) NewInstance() KeyStoreAdapter {
	return NewBoltKS()
}

func (ks *BoltKS) Initialized() bool {
	return ks.db != nil
}

func (ks *BoltKS) Create(alias string, key []byte) error {
	err := ks.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(vsmBucket))
		aliasBytes := []byte(alias)
		v := bucket.Get(aliasBytes)
		if v != nil {
			return util.ErrAlreadyExists
		}

		return bucket.Put(aliasBytes, key)
	})
	if err != nil {
		return translateBoltError(err)
	}

	return nil
}

func (ks *BoltKS) Read(alias string) ([]byte, error) {
	var result []byte

	err := ks.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(vsmBucket))
		v := bucket.Get([]byte(alias))
		if v == nil {
			return util.ErrNotFound
		}

		result = make([]byte, len(v))
		copy(result, v)

		return nil
	})
	if err != nil {
		return []byte{}, translateBoltError(err)
	}

	return result, nil
}

func (ks *BoltKS) Delete(alias string) error {
	err := ks.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(vsmBucket))
		aliasBytes := []byte(alias)
		v := bucket.Get(aliasBytes)
		if v == nil {
			return util.ErrNotFound
		}

		return bucket.Delete(aliasBytes)
	})
	if err != nil {
		return translateBoltError(err)
	}

	return nil
}

func (ks *BoltKS) Type() string {
	return boltKSType
}

func (ks *BoltKS) Location() string {
	return ""
}

func translateBoltError(boltError error) error {
	return boltError
}
