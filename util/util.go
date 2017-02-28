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

func WriteErrorResponse(w http.ResponseWriter, e error, statusCode int) {
	b, _ := json.Marshal(e.Error())
	http.Error(w, string(b), statusCode)
}

func WriteResponse(w http.ResponseWriter, v interface{}, statusCode int) {
	w.WriteHeader(statusCode)
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "%v", string(b))
}