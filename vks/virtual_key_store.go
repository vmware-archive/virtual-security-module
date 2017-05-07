// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"encoding/json"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/crypt"
	"log"
)

// An implementation of a virtual key store over a collection of key stores using Polynomial Secret Sharing.
type VirtualKeyStore struct {
	keyStores         []KeyStoreAdapter
	keyStoreCount     int
	keyStoreThreshold int
	secretSharer      *crypt.SecretSharer
	initialized       bool
}

func NewVirtualKeyStore() *VirtualKeyStore {
	return &VirtualKeyStore{}
}

func (vks *VirtualKeyStore) Init(cfg *config.Config) error {
	vKeyStore, err := GetVirtualKeyStoreFromConfig(cfg)
	if err != nil {
		return err
	}

	vks.keyStores = vKeyStore.keyStores
	vks.keyStoreCount = vKeyStore.keyStoreCount
	vks.keyStoreThreshold = vKeyStore.keyStoreThreshold
	vks.secretSharer = vKeyStore.secretSharer
	vks.initialized = vKeyStore.initialized

	return nil
}

func (vks *VirtualKeyStore) CompleteInit(*config.Config) error {
	return nil
}

func (vks *VirtualKeyStore) Initialized() bool {
	return vks.initialized
}

func (vks *VirtualKeyStore) Create(alias string, key []byte) error {
	shares := vks.secretSharer.BreakSecret(key)

	successCount := 0
	var lastError error = nil

	// concurrently create shares in underlying key stores
	errors := make(chan error, len(shares))
	for i, share := range shares {
		go createShareInKeyStore(vks.keyStores[i], alias, share, errors)
	}

	// collect results
	for i := 0; i < len(shares); i++ {
		err := <-errors
		if err != nil {
			log.Printf("WARNING: failed to create alias %s in a key store: %v", alias, err)
			lastError = err
		} else {
			successCount++
		}
	}
	close(errors)

	if successCount >= vks.keyStoreThreshold {
		return nil
	}

	return lastError
}

func (vks *VirtualKeyStore) Read(alias string) ([]byte, error) {
	shares := []*crypt.SecretShare{}

	successCount := 0
	var lastError error = nil

	// concurrently read shares from underlying key stores
	sharesCh := make(chan *crypt.SecretShare, vks.keyStoreCount)
	errors := make(chan error, vks.keyStoreCount)
	for _, ks := range vks.keyStores {
		go readShareFromKeyStore(ks, alias, sharesCh, errors)
	}

	// collect results
	for i := 0; i < vks.keyStoreCount; i++ {
		err := <-errors
		share := <-sharesCh
		if err != nil {
			log.Printf("WARNING: failed to read alias %s: %v", alias, err)
			lastError = err
		} else {
			shares = append(shares, share)
			successCount++
		}
	}
	close(errors)
	close(sharesCh)

	if successCount < vks.keyStoreThreshold {
		return []byte{}, lastError
	}

	return vks.secretSharer.ReconstructSecret(shares)
}

func (vks *VirtualKeyStore) Delete(alias string) error {
	successCount := 0
	var lastError error = nil

	// concurrently delete shares from underlying key stores
	errors := make(chan error, vks.keyStoreCount)
	for _, ks := range vks.keyStores {
		go deleteShareFromKeyStore(ks, alias, errors)
	}

	// collect results
	for i := 0; i < vks.keyStoreCount; i++ {
		err := <-errors
		if err != nil {
			log.Printf("WARNING: failed to delete alias %s: %v", alias, err)
			lastError = err
		} else {
			successCount++
		}
	}
	close(errors)

	// we return an error iff there are enough shares left to reconstruct the key
	undeletedSharesCount := vks.keyStoreCount - successCount
	if undeletedSharesCount >= vks.keyStoreThreshold {
		return lastError
	}

	return nil
}

func createShareInKeyStore(ks KeyStoreAdapter, alias string, share *crypt.SecretShare, errors chan error) {
	b, err := json.Marshal(*share)
	if err != nil {
		errors <- err
		return
	}

	err = ks.Create(alias, b)
	errors <- err
}

func readShareFromKeyStore(ks KeyStoreAdapter, alias string, shares chan *crypt.SecretShare, errors chan error) {
	b, err := ks.Read(alias)
	if err != nil {
		errors <- err
		shares <- nil
		return
	}

	var share crypt.SecretShare
	if err := json.Unmarshal(b, &share); err != nil {
		errors <- err
		shares <- nil
		return
	}

	shares <- &share
	errors <- nil
}

func deleteShareFromKeyStore(ks KeyStoreAdapter, alias string, errors chan error) {
	errors <- ks.Delete(alias)
}
