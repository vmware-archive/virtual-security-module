// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package context

import (
	gocontext "context"
)

type RequestContextKey string

const RequestContextKeyUsername = RequestContextKey("username")

func GetSystemRequestContext() gocontext.Context {
	return gocontext.WithValue(gocontext.Background(), RequestContextKeyUsername, "root")
}
