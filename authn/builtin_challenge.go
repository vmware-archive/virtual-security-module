// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"time"
	
	"github.com/vmware/virtual-security-module/util"
)

type BuiltinChallenge struct {
	Uuid string
	Username string
	Random	[]byte
	GoodUntil time.Time
}

func NewBuiltinChallenge(username string) (*BuiltinChallenge, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err	
	}
	
	return &BuiltinChallenge{
		Uuid: util.NewUUID(),
		Username: username,
		Random: buf,
		GoodUntil: time.Now().Add(time.Minute),
	}, nil
}

func (challenge *BuiltinChallenge) Encode() ([]byte, error) {
	b, err := json.Marshal(challenge)
	if err != nil {
		return nil, err
	}
	
	return b, nil
}

func (challenge *BuiltinChallenge) Decode(encodedChallenge []byte) error {
	return json.Unmarshal(encodedChallenge, challenge)
}

func (challenge *BuiltinChallenge) Equal(challenge2 *BuiltinChallenge) bool {
	return (challenge.Uuid == challenge2.Uuid) &&
		(challenge.Username == challenge2.Username) &&
		bytes.Equal(challenge.Random, challenge2.Random) &&
		challenge.GoodUntil.Equal(challenge2.GoodUntil) 
}

func (challenge *BuiltinChallenge) Expired() bool {
	return challenge.GoodUntil.Before(time.Now())
}