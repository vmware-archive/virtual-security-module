// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ValidationError struct {
	Reason string
}

func (v *ValidationError) Error() string {
	return fmt.Sprintf("{ValidationError: {'reason': %v}}", v.Reason)
}

func ExtractAndValidateSecretEntry(req *http.Request) (*SecretEntry, error) {
	decoder := json.NewDecoder(req.Body)
    var secretEntry SecretEntry
    if err := decoder.Decode(&secretEntry); err != nil {
        return nil, &ValidationError{Reason: err.Error()}
    }
    defer req.Body.Close()

    if len(secretEntry.SecretData) == 0 {
	return nil, &ValidationError{Reason: "empty secretData"}
    }

    return &secretEntry, nil
}