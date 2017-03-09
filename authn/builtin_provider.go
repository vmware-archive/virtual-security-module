// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	
	"github.com/dgrijalva/jwt-go"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/crypt"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
	"github.com/vmware/virtual-security-module/util"
)

const pType = "Builtin"

func init() {
	if err := AuthnProviderRegistrar.Register(pType, NewBuiltinProvider()); err != nil {
		panic(fmt.Sprintf("Failed to register authn provider type %v: %v", pType, err))
	}
}

type BuiltinProvider struct {
	dataStore vds.DataStoreAdapter
	keyStore vks.KeyStoreAdapter
	tokenSigningKey []byte
	challenges map[string]*BuiltinChallenge
}

func NewBuiltinProvider() *BuiltinProvider {
	return &BuiltinProvider{
	}
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

func (p *BuiltinProvider) Login(l *model.LoginRequest) (token string, e error) {
	loginFailedErr := fmt.Errorf("login user %v failed", l.Username)
	
	if l.Challenge == "" {
		// first phase of login: generate a challenge from the user's public
		// key and send to client
		entryId := p.usernameToEntryId(l.Username)
		
		dataStoreEntry, err1 := p.dataStore.ReadEntry(entryId)
		key, err2 := p.keyStore.Read(entryId)
		if err1 != nil || err2 != nil {
			// if the user doesn't exist, we generate and return a fake
			// challenge, rather than failing, so that the attacker would
			// not be able to tell whether the user exists
			fakeChallenge, err := p.generateFakeChallenge(l.Username)
			if err != nil {
				return "", loginFailedErr
			}
			return fakeChallenge, nil
		}
		
		userEntry, err := vds.DataStoreEntryToUserEntry(dataStoreEntry)
		if err != nil {
			return "", loginFailedErr
		}
		
		// credentials is the user's public key
		credentials, err := crypt.Decrypt(userEntry.Credentials, key)
		if err != nil {
			return "", loginFailedErr
		}
	
		challenge, err := p.generateChallenge(l.Username, credentials)
		if err != nil {
			return "", loginFailedErr
		}
		
		return challenge, nil
	}
	
	// second phase of login: verify challenge and generate a token.
	// the challenge must have been decrypted using the user's private key
	tokenStr, err := p.verifyChallengeAndGenerateToken(l.Challenge)
	if err != nil {
		return "", loginFailedErr
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
		return "", fmt.Errorf("Id %v already exists", userEntry.Username)
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
		return "", err
	}

	ue := &model.UserEntry{
		Username: userEntry.Username,
		Credentials: encryptedCredentials,
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

func (p *BuiltinProvider) usernameToEntryId(username string) string {
	return username
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
	
	return string(cipherText), nil
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