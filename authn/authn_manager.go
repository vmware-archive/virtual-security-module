// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	gocontext "context"
	"net/http"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

const (
	HeaderNameAuth = "Authorization"
	LoginPath      = "/login"
	UsersPath      = "/users"
)

type AuthnProvider interface {
	Init(*config.Config, vds.DataStoreAdapter, *vks.VirtualKeyStore) error
	Authenticated(r *http.Request) (username string, e error)
	Login(l *model.LoginRequest) (token string, e error)
	CreateUser(*model.UserEntry) (string, error)
	DeleteUser(username string) error
	GetUser(username string) (*model.UserEntry, error)
	Type() string
}

var authnProviderRegistry map[string]AuthnProvider = make(map[string]AuthnProvider)

type AuthnManager struct {
	whitelist     map[string]bool
	authnProvider AuthnProvider
	authzManager  context.AuthorizationManager
}

func New() *AuthnManager {
	return &AuthnManager{}
}

func (authnManager *AuthnManager) Type() string {
	return "AuthnManager"
}

func (authnManager *AuthnManager) Init(moduleInitContext *context.ModuleInitContext) error {
	authnProvider := NewBuiltinProvider()
	if err := authnProvider.Init(nil, moduleInitContext.DataStore, moduleInitContext.VirtualKeyStore); err != nil {
		return err
	}

	authnManager.whitelist = map[string]bool{LoginPath: true}
	authnManager.authnProvider = authnProvider
	authnManager.authzManager = moduleInitContext.AuthzManager

	return nil
}

func (authNManager *AuthnManager) Close() error {
	return nil
}

func (authNManager *AuthnManager) HandlePre(w http.ResponseWriter, r *http.Request) *http.Request {
	path := r.URL.Path
	_, ok := authNManager.whitelist[path]
	if ok {
		return r
	}

	username, err := authNManager.authnProvider.Authenticated(r)
	if err != nil {
		util.WriteErrorStatus(w, util.ErrUnauthorized)
		return nil
	}

	newContext := gocontext.WithValue(r.Context(), context.RequestContextKeyUsername, username)
	newRequest := r.WithContext(newContext)

	return newRequest
}

func (authnManager *AuthnManager) Login(l *model.LoginRequest) (string, error) {
	return authnManager.authnProvider.Login(l)
}

func (authnManager *AuthnManager) CreateUser(ctx gocontext.Context, userEntry *model.UserEntry) (string, error) {
	if err := authnManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpCreate}, UsersPath); err != nil {
		return "", err
	}

	return authnManager.authnProvider.CreateUser(userEntry)
}

func (authnManager *AuthnManager) DeleteUser(ctx gocontext.Context, username string) error {
	if err := authnManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpDelete}, UsersPath); err != nil {
		return err
	}

	return authnManager.authnProvider.DeleteUser(username)
}

func (authnManager *AuthnManager) GetUser(ctx gocontext.Context, username string) (*model.UserEntry, error) {
	if err := authnManager.authzManager.Allowed(ctx, model.Operation{Label: model.OpRead}, UsersPath); err != nil {
		return nil, err
	}

	return authnManager.authnProvider.GetUser(username)
}
