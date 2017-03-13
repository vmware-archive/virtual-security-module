// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package util

import (
	"encoding/json"
	"fmt"
	"net/http"

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

func WriteErrorResponse(w http.ResponseWriter, e error) {
	w.WriteHeader(HttpStatus(e))
	if err := json.NewEncoder(w).Encode(e.Error()); err != nil {
		fmt.Printf("WARNING: failed to encode error %v: %v\n", e, err)
	}
}

func WriteErrorStatus(w http.ResponseWriter, e error) {
	w.WriteHeader(HttpStatus(e))
}

func WriteResponse(w http.ResponseWriter, v interface{}, statusCode int) {
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Printf("WARNING: failed to encode %v: %v\n", v, err)
	}
}

func WriteStatus(w http.ResponseWriter, statusCode int) {
	w.WriteHeader(statusCode)
}