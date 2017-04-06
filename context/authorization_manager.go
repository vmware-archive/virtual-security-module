// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package context

import (
	gocontext "context"

	"github.com/vmware/virtual-security-module/model"
)

type AuthorizationManager interface {
	Allowed(ctx gocontext.Context, op model.Operation, namespacePath string) error
}
