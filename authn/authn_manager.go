// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"net/http"
	
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/secret"
)

const (
	HeaderNameAuth = "Authorization"
)

type AuthnProvider interface {
	Init(map[string]*config.ConfigProperty, *secret.SecretManager) error
	Authenticated(r *http.Request) (username string, e error)
	Login(l *model.LoginRequest, creds []byte) (token string, e error)
	Type() string
}

var authnProviderRegistry map[string]AuthnProvider = make(map[string]AuthnProvider)

type AuthnManager struct {
	whitelist []string
	authnProvider AuthnProvider
	tokenToUserId map[string]string
}

func New() *AuthnManager {
	return &AuthnManager{}
}

func (authnManager *AuthnManager) Type() string {
	return "AuthnManager"
}

func (authnManager *AuthnManager) Init(configItems map[string]*config.ConfigItem) error {
	return nil//authnManager.initFromConfig(configItems)
}

func (authNManager *AuthnManager) Close() error {
	return nil
}