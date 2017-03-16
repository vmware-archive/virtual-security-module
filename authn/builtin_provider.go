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
	keyStore        vks.KeyStoreAdapter
	tokenSigningKey []byte
	challenges      map[string]*BuiltinChallenge
}

func NewBuiltinProvider() *BuiltinProvider {
	return &BuiltinProvider{}
}

func (p *BuiltinProvider) Init(configProps map[string]*config.ConfigProperty, ds vds.DataStoreAdapter, ks vks.KeyStoreAdapter) error {
	tokenSigningKey, err := crypt.GenerateKey()
	if err != nil {
		return err
	}

	p.dataStore = ds
	p.keyStore = ks
	p.tokenSigningKey = tokenSigningKey
	p.challenges = make(map[string]*BuiltinChallenge)

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
		entryId := l.Username

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
	_, err := p.dataStore.ReadEntry(userEntry.Username)
	if err == nil {
		return "", util.ErrAlreadyExists
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

	ue := &model.UserEntry{
		Username:     userEntry.Username,
		Credentials:  encryptedCredentials,
		RoleEntryIds: userEntry.RoleEntryIds,
	}

	// create a data store entry and save it
	dataStoreEntry, err := vds.UserEntryToDataStoreEntry(ue)
	if err != nil {
		return "", err
	}
	if err := p.dataStore.WriteEntry(dataStoreEntry); err != nil {
		return "", err
	}

	// persist key using virtual key store
	if err := p.keyStore.Write(ue.Username, key); err != nil {
		return "", err
	}

	return ue.Username, nil
}

func (p *BuiltinProvider) DeleteUser(username string) error {
	if err := p.dataStore.DeleteEntry(username); err != nil {
		return err
	}

	if err := p.keyStore.Delete(username); err != nil {
		return err
	}

	return nil
}

func (p *BuiltinProvider) GetUser(username string) (*model.UserEntry, error) {
	dataStoreEntry, err := p.dataStore.ReadEntry(username)
	if err != nil {
		return nil, err
	}

	key, err := p.keyStore.Read(username)
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

	ue := &model.UserEntry{
		Username:     userEntry.Username,
		Credentials:  credentials,
		RoleEntryIds: userEntry.RoleEntryIds,
	}

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
	challenge, err := NewBuiltinChallenge(username)
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

	if !fake {
		p.challenges[challenge.Uuid] = challenge
		time.AfterFunc(challenge.GoodUntil.Sub(time.Now()), func() {
			delete(p.challenges, challenge.Uuid)
		})
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

	if challenge.Uuid == "" {
		return "", fmt.Errorf("challenge id is empty")
	}

	originalChallenge, ok := p.challenges[challenge.Uuid]
	if !ok {
		return "", fmt.Errorf("challenge id not found")
	}

	if !originalChallenge.Equal(challenge) || originalChallenge.Expired() {
		return "", fmt.Errorf("challenge mismatch")
	}

	delete(p.challenges, challenge.Uuid)

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": challenge.Username,
	})
	tString, err := t.SignedString(p.tokenSigningKey)
	if err != nil {
		return "", err
	}

	return tString, nil
}
