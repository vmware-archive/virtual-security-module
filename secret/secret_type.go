// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	gocontext "context"

	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
)

type SecretType interface {
	Type() string
	Init(*context.ModuleInitContext) error
	CreateSecret(gocontext.Context, *model.SecretEntry) (string, error)
	GetSecret(gocontext.Context, *model.SecretEntry) (*model.SecretEntry, error)
	DeleteSecret(gocontext.Context, *model.SecretEntry) error
}
