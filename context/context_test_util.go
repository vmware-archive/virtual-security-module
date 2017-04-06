// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package context

import (
	gocontext "context"

	"github.com/vmware/virtual-security-module/model"
)

func GetTestAuthzManager() AuthorizationManager {
	return &testAuthzManager{}
}

func GetTestRequestContext() gocontext.Context {
	return GetSystemRequestContext()
}

type testAuthzManager struct{}

func (t *testAuthzManager) Allowed(ctx gocontext.Context, op model.Operation, namespacePath string) error {
	return nil
}
