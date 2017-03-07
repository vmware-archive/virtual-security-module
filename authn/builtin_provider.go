// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"fmt"
	"net/http"
	"strings"
	
	"github.com/dgrijalva/jwt-go"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/crypt"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/secret"
)

const pType = "Builtin"

func init() {
	if err := AuthnProviderRegistrar.Register(pType, NewBuiltinProvider()); err != nil {
		panic(fmt.Sprintf("Failed to register authn provider type %v: %v", pType, err))
	}
}

type BuiltinProvider struct {
	secretManager *secret.SecretManager
	tokenSigningKey []byte
}

func NewBuiltinProvider() AuthnProvider {
	return &BuiltinProvider{
	}
}

func (p *BuiltinProvider) Init(configProps map[string]*config.ConfigProperty, secretManager *secret.SecretManager) error {
	tokenSigningKey, err := crypt.GenerateKey()
	if err != nil {
		return err
	}
	
	p.secretManager = secretManager
	p.tokenSigningKey = tokenSigningKey
	
	return nil
}

func (p *BuiltinProvider) Authenticated(r *http.Request) (username string, e error) {
	if r.Header == nil {
		return "", fmt.Errorf("%v header not found", HeaderNameAuth)
	}
	
	authHeader := r.Header.Get(HeaderNameAuth)
	if authHeader == "" {
		return "", fmt.Errorf("%v header not found", HeaderNameAuth)
	}
	
	schemaAndToken := strings.Fields(authHeader)
	if len(schemaAndToken) != 2 {
		return "", fmt.Errorf("%v header %v must have the format <schema> <token>", HeaderNameAuth, authHeader)
	}
	
	tokenString := schemaAndToken[1]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	    // Verifying that the signing alg is what we used
	    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	    }
	
	    return p.tokenSigningKey, nil
	})
	
	if err != nil || !token.Valid {
		return "", fmt.Errorf("validation of token %v failed: %v", tokenString, err.Error())
	}
	
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("could not find claims map in token %v", tokenString)
	}
	
	nameClaim, ok := claims["name"]
	if !ok {
		return "", fmt.Errorf("could not find name claim")
	}
	
	user, ok := nameClaim.(string)
	if !ok {
		return "", fmt.Errorf("name claim %v is not a string", nameClaim)
	}
	
	return user, nil
}

func (p *BuiltinProvider) Login(l *model.LoginRequest, creds []byte) (token string, e error) {
	entryId := p.usernameToEntryId(l.Username)
	
	// TODO: user p.secretManager to 'login' (get descrypted user and creds and compare)
	
	return entryId, nil
}

func (p *BuiltinProvider) Type() string {
	return pType
}

func (p *BuiltinProvider) usernameToEntryId(username string) string {
	return username
}