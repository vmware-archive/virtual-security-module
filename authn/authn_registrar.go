// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package authn

import (
	"fmt"
)

// singleton registrar for authN providers
var AuthnProviderRegistrar *authnProviderRegistrar = newRegistrar()

type authnProviderRegistrar struct {
	providers map[string]AuthnProvider
}

func newRegistrar() *authnProviderRegistrar {
	return &authnProviderRegistrar{
		providers: make(map[string]AuthnProvider),
	}
}

func (pRegistrar *authnProviderRegistrar) Register(pType string, p AuthnProvider) error {
	_, ok := pRegistrar.providers[pType]
	if ok {
		return fmt.Errorf("authn provider of type %v already registered", pType)
	}

	pRegistrar.providers[pType] = p

	return nil
}

func (pRegistrar *authnProviderRegistrar) Unregister(pType string) error {
	_, ok := pRegistrar.providers[pType]
	if !ok {
		return fmt.Errorf("authn provider of type %v not registered", pType)
	}

	delete(pRegistrar.providers, pType)

	return nil
}

func (pRegistrar *authnProviderRegistrar) Registered(pType string) bool {
	_, ok := pRegistrar.providers[pType]

	return ok
}

func (pRegistrar *authnProviderRegistrar) Get(pType string) (AuthnProvider, error) {
	p, ok := pRegistrar.providers[pType]

	if !ok {
		return nil, fmt.Errorf("authn provider of type %v not registered", pType)
	}

	return p, nil
}
