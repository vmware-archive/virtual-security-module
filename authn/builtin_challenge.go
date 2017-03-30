// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"time"
)

const FIXED = "builtin-challenge"

type BuiltinChallenge struct {
	Fixed     string
	Username  string
	Random    []byte
	GoodUntil time.Time
}

func NewBuiltinChallenge(username string) (*BuiltinChallenge, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return &BuiltinChallenge{
		Fixed:     FIXED,
		Username:  username,
		Random:    buf,
		GoodUntil: time.Now().Add(time.Minute),
	}, nil
}

func NewFakeBuiltinChallenge(username string) (*BuiltinChallenge, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return &BuiltinChallenge{
		Fixed:     "INVALID",
		Username:  username,
		Random:    buf,
		GoodUntil: time.Now().Add(-time.Hour),
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
	return (challenge.Fixed == challenge2.Fixed) &&
		(challenge.Username == challenge2.Username) &&
		bytes.Equal(challenge.Random, challenge2.Random) &&
		challenge.GoodUntil.Equal(challenge2.GoodUntil)
}

func (challenge *BuiltinChallenge) Expired() bool {
	return challenge.GoodUntil.Before(time.Now())
}

func (challenge *BuiltinChallenge) Valid() bool {
	return challenge.Fixed == FIXED && !challenge.Expired()
}
