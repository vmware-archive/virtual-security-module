// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/util"
)

// singleton registrar for secret types
var SecretTypeRegistrar *secretTypeRegistrar = newRegistrar()

type secretTypeRegistrar struct {
	secretTypes map[string]SecretType
}

func newRegistrar() *secretTypeRegistrar {
	return &secretTypeRegistrar{
		secretTypes: make(map[string]SecretType),
	}
}

func (stRegistrar *secretTypeRegistrar) Register(typeName string, secretType SecretType) error {
	_, ok := stRegistrar.secretTypes[typeName]
	if ok {
		return util.ErrAlreadyExists
	}

	stRegistrar.secretTypes[typeName] = secretType

	return nil
}

func (stRegistrar *secretTypeRegistrar) Unregister(typeName string) error {
	_, ok := stRegistrar.secretTypes[typeName]
	if !ok {
		return util.ErrNotFound
	}

	delete(stRegistrar.secretTypes, typeName)

	return nil
}

func (stRegistrar *secretTypeRegistrar) Registered(typeName string) bool {
	_, ok := stRegistrar.secretTypes[typeName]

	return ok
}

func (stRegistrar *secretTypeRegistrar) Get(typeName string) (SecretType, error) {
	secretType, ok := stRegistrar.secretTypes[typeName]

	if !ok {
		return nil, util.ErrNotFound
	}

	return secretType, nil
}

func (stRegistrar *secretTypeRegistrar) InitSecretTypes(moduleInitContext *context.ModuleInitContext) error {
	for _, st := range stRegistrar.secretTypes {
		if err := st.Init(moduleInitContext); err != nil {
			return err
		}
	}

	return nil
}
