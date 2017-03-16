// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package util

import (
	"net/http"

	"errors"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrAlreadyExists   = errors.New("already exists")
	ErrInputValidation = errors.New("input validation error")
	ErrUnauthorized    = errors.New("unauthorized error")
	ErrInternal        = errors.New("internal error")
)

func HttpStatus(err error) int {
	switch err {
	case ErrNotFound:
		return http.StatusNotFound
	case ErrAlreadyExists:
		return http.StatusConflict
	case ErrInputValidation:
		return http.StatusBadRequest
	case ErrUnauthorized:
		return http.StatusForbidden
	case ErrInternal:
		return http.StatusInternalServerError
	}

	return http.StatusInternalServerError
}
