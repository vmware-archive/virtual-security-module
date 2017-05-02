// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/crypt"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

const pType = "Builtin"

func init() {
	if err := AuthnProviderRegistrar.Register(pType, NewBuiltinProvider()); err != nil {
		panic(fmt.Sprintf("Failed to register authn provider type %v: %v", pType, err))
	}
}

type BuiltinProvider struct {
	dataStore       vds.DataStoreAdapter
	keyStore        *vks.VirtualKeyStore
	tokenSigningKey []byte
}

func NewBuiltinProvider() *BuiltinProvider {
	return &BuiltinProvider{}
}

func (p *BuiltinProvider) Init(config *config.Config, ds vds.DataStoreAdapter, ks *vks.VirtualKeyStore) error {
	tokenSigningKey, err := crypt.GenerateKey()
	if err != nil {
		return err
	}

	p.dataStore = ds
	p.keyStore = ks
	p.tokenSigningKey = tokenSigningKey

	return nil
}

func (p *BuiltinProvider) Authenticated(r *http.Request) (username string, e error) {
	if r.Header == nil {
		return "", util.ErrInputValidation
	}

	authHeader := r.Header.Get(HeaderNameAuth)
	if authHeader == "" {
		return "", util.ErrInputValidation
	}

	schemaAndToken := strings.Fields(authHeader)
	if len(schemaAndToken) != 2 {
		return "", util.ErrInputValidation
	}

	tokenString := schemaAndToken[1]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verifying that the signing alg is what we used
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, util.ErrInputValidation
		}

		return p.tokenSigningKey, nil
	})

	if err != nil || !token.Valid {
		return "", util.ErrInputValidation
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", util.ErrInputValidation
	}

	nameClaim, ok := claims["name"]
	if !ok {
		return "", util.ErrInputValidation
	}

	user, ok := nameClaim.(string)
	if !ok {
		return "", util.ErrInputValidation
	}

	return user, nil
}

func (p *BuiltinProvider) Login(l *model.LoginRequest) (token string, e error) {
	if l.Challenge == "" {
		// first phase of login: generate a challenge from the user's public
		// key and send to client
		entryId := vds.UsernameToPath(l.Username)

		dataStoreEntry, err1 := p.dataStore.ReadEntry(entryId)
		key, err2 := p.keyStore.Read(entryId)
		if err1 != nil || err2 != nil {
			// if the user doesn't exist, we generate and return a fake
			// challenge, rather than failing, so that the attacker would
			// not be able to tell whether the user exists
			fakeChallenge, err := p.generateFakeChallenge(l.Username)
			if err != nil {
				return "", util.ErrUnauthorized
			}
			return fakeChallenge, nil
		}

		userEntry, err := vds.DataStoreEntryToUserEntry(dataStoreEntry)
		if err != nil {
			return "", util.ErrUnauthorized
		}

		// credentials is the user's public key
		credentials, err := crypt.Decrypt(userEntry.Credentials, key)
		if err != nil {
			return "", util.ErrUnauthorized
		}

		challenge, err := p.generateChallenge(l.Username, credentials)
		if err != nil {
			return "", util.ErrUnauthorized
		}

		return challenge, nil
	}

	// second phase of login: verify challenge and generate a token.
	// the challenge must have been decrypted using the user's private key
	tokenStr, err := p.verifyChallengeAndGenerateToken(l.Challenge)
	if err != nil {
		return "", util.ErrUnauthorized
	}

	return tokenStr, nil
}

func (p *BuiltinProvider) Type() string {
	return pType
}

func (p *BuiltinProvider) CreateUser(userEntry *model.UserEntry) (string, error) {
	// verify user doesn't exist
	userpath := vds.UsernameToPath(userEntry.Username)
	if _, err := p.dataStore.ReadEntry(userpath); err == nil {
		return "", util.ErrAlreadyExists
	}

	// verify roles' scopes exist
	for _, role := range userEntry.Roles {
		namespacePath := role.Scope
		if !strings.HasPrefix(namespacePath, "/") {
			return "", util.ErrInputValidation
		}

		dsEntry, err := p.dataStore.ReadEntry(namespacePath)
		if err != nil {
			return "", util.ErrInputValidation
		}

		if !vds.IsNamespaceEntry(dsEntry) {
			return "", util.ErrInputValidation
		}
	}

	// generate encryption key for user entry
	key, err := crypt.GenerateKey()
	if err != nil {
		return "", err
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	// encrypt user credentials using key
	encryptedCredentials, err := crypt.Encrypt(userEntry.Credentials, key)
	if err != nil {
		return "", util.ErrInternal
	}

	ue := model.NewUserEntry(userEntry)
	ue.Credentials = encryptedCredentials

	// create a data store entry and save it
	dataStoreEntry, err := vds.UserEntryToDataStoreEntry(ue)
	if err != nil {
		return "", err
	}
	if err := p.dataStore.CreateEntry(dataStoreEntry); err != nil {
		return "", err
	}

	// persist key using virtual key store
	if err := p.keyStore.Create(userpath, key); err != nil {
		return "", err
	}

	return ue.Username, nil
}

func (p *BuiltinProvider) DeleteUser(username string) error {
	userpath := vds.UsernameToPath(username)

	if err := p.dataStore.DeleteEntry(userpath); err != nil {
		return err
	}

	if err := p.keyStore.Delete(userpath); err != nil {
		return err
	}

	return nil
}

func (p *BuiltinProvider) GetUser(username string) (*model.UserEntry, error) {
	userpath := vds.UsernameToPath(username)

	dataStoreEntry, err := p.dataStore.ReadEntry(userpath)
	if err != nil {
		return nil, err
	}

	key, err := p.keyStore.Read(userpath)
	if err != nil {
		return nil, err
	}

	// reduce key exposure due to memory compromize / leak
	defer util.Memzero(key)

	userEntry, err := vds.DataStoreEntryToUserEntry(dataStoreEntry)
	if err != nil {
		return nil, err
	}

	// credentials is the user's public key
	credentials, err := crypt.Decrypt(userEntry.Credentials, key)
	if err != nil {
		return nil, util.ErrInternal
	}

	ue := model.NewUserEntry(userEntry)
	ue.Credentials = credentials

	return ue, nil
}

func (p *BuiltinProvider) generateChallenge(username string, publicKeyBytes []byte) (string, error) {
	var publicKey rsa.PublicKey
	if err := json.Unmarshal(publicKeyBytes, &publicKey); err != nil {
		return "", err
	}

	return p.genChallenge(username, &publicKey, false)
}

func (p *BuiltinProvider) generateFakeChallenge(username string) (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	return p.genChallenge(username, &privateKey.PublicKey, true)
}

func (p *BuiltinProvider) genChallenge(username string, publicKey *rsa.PublicKey, fake bool) (string, error) {
	challenge, err := NewFakeBuiltinChallenge(username)
	if err != nil {
		return "", err
	}

	if !fake {
		challenge, err = NewBuiltinChallenge(username)
	}
	if err != nil {
		return "", err
	}

	b, err := challenge.Encode()
	if err != nil {
		return "", err
	}

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, b)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (p *BuiltinProvider) verifyChallengeAndGenerateToken(challengeStr string) (string, error) {
	challenge, err := NewBuiltinChallenge("")
	if err != nil {
		return "", err
	}
	if err := challenge.Decode([]byte(challengeStr)); err != nil {
		return "", err
	}

	if !challenge.Valid() {
		return "", fmt.Errorf("challenge is invalid")
	}

	expirationTime := time.Now().Add(time.Hour)
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": challenge.Username,
		"exp":  expirationTime.Unix(),
	})
	tString, err := t.SignedString(p.tokenSigningKey)
	if err != nil {
		return "", err
	}

	return tString, nil
}
