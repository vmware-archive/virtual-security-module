// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
)

type SecretType interface {
	Type() string
	Init(*context.ModuleInitContext) error
	CreateSecret(*model.SecretEntry) (string, error)
	GetSecret(*model.SecretEntry) (*model.SecretEntry, error)
	DeleteSecret(*model.SecretEntry) error
}
