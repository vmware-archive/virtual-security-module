// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"net/http"
	
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

const (
	HeaderNameAuth = "Authorization"
	LoginPath = "/login"
)

type AuthnProvider interface {
	Init(map[string]*config.ConfigProperty, vds.DataStoreAdapter, vks.KeyStoreAdapter) error
	Authenticated(r *http.Request) (username string, e error)
	Login(l *model.LoginRequest) (token string, e error)
	CreateUser(*model.UserEntry) (string, error)
	DeleteUser(username string) error
	GetUser(username string) (*model.UserEntry, error)
	Type() string
}

var authnProviderRegistry map[string]AuthnProvider = make(map[string]AuthnProvider)

type AuthnManager struct {
	whitelist []string
	authnProvider AuthnProvider
}

func New() *AuthnManager {
	return &AuthnManager{}
}

func (authnManager *AuthnManager) Type() string {
	return "AuthnManager"
}

func (authnManager *AuthnManager) Init(configItems map[string]*config.ConfigItem, ds vds.DataStoreAdapter, ks vks.KeyStoreAdapter) error {
	authnProvider := NewBuiltinProvider()
	if err := authnProvider.Init(nil, ds, ks); err != nil {
		return err
	}
	
	authnManager.authnProvider = authnProvider
	
	authnManager.whitelist = []string{ LoginPath }
	
	return nil
}

func (authNManager *AuthnManager) Close() error {
	return nil
}

func (authnManager *AuthnManager) Login(l *model.LoginRequest) (string, error) {
	return authnManager.authnProvider.Login(l)
}

func (authnManager *AuthnManager) CreateUser(userEntry *model.UserEntry) (string, error) {
	return authnManager.authnProvider.CreateUser(userEntry)
}

func (authnManager *AuthnManager) DeleteUser(username string) error {
	return authnManager.authnProvider.DeleteUser(username)
}

func (authnManager *AuthnManager) GetUser(username string) (*model.UserEntry, error) {
	return authnManager.authnProvider.GetUser(username)
}