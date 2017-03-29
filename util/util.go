// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/satori/go.uuid"
)

func Memzero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func NewUUID() string {
	return uuid.NewV4().String()
}

func WriteErrorResponse(w http.ResponseWriter, e error) error {
	w.WriteHeader(HttpStatus(e))
	return json.NewEncoder(w).Encode(e.Error())
}

func WriteErrorStatus(w http.ResponseWriter, e error) {
	w.WriteHeader(HttpStatus(e))
}

func WriteResponse(w http.ResponseWriter, v interface{}, statusCode int) error {
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(v)
}

func WriteStatus(w http.ResponseWriter, statusCode int) {
	w.WriteHeader(statusCode)
}

func ReadRSAPublicKey(filename string) (*rsa.PublicKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public key from file %v: %v", filename, err)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("Failed to decode public key from file %v", filename)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key from file %v: %v", filename, err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Public key from file %v is not a RSA public key", filename)
	}

	return rsaPubKey, nil
}

func ReadRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private key from file %v: %v", filename, err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode private key from file %v", filename)
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key from file %v: %v", filename, err)
	}

	return privKey, nil
}

func JSONPrettyPrint(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func GetChildSearchPattern(path string) string {
	if strings.HasSuffix(path, "/") {
		return path + "?*"
	} else {
		return path + "/?*"
	}
}

func CheckPort(port int) error {
	if (port < 0) || (port > 65535) {
		return fmt.Errorf("Port should between 0 and 65535")
	}

	return nil
}
