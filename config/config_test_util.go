// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

func GenerateTestConfig() *Config {
	config := &Config{
		ServerConfig: ServerConfig{
			HttpConfig: HttpConfig{
				Enabled: true,
				Port:    8090,
			},
			HttpsConfig: HttpsConfig{
				Enabled:    true,
				CaCert:     "../certs/test-root-cert.pem",
				CaKey:      "../certs/test-root-key.pem",
				ServerCert: "../certs/test-server-cert.pem",
				ServerKey:  "../certs/test-server-key.pem",
				Port:       8444,
			},
			RootInitPubKey:     "../certs/test-root-init-public.pem",
			RootInitPrivateKey: "../certs/test-root-init-private.pem",
		},
		DataStoreConfig: DataStoreConfig{
			StoreType: "InMemoryDataStore",
		},
		VirtualKeyStoreConfig: VirtualKeyStoreConfig{
			KeyStoreCount:     3,
			KeyStoreThreshold: 2,
			KeyStores: []KeyStoreConfig{
				KeyStoreConfig{StoreType: "InMemoryKeyStore"},
				KeyStoreConfig{StoreType: "InMemoryKeyStore"},
				KeyStoreConfig{StoreType: "InMemoryKeyStore"},
			},
		},
	}

	return config
}
