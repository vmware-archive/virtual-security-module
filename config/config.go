// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

var DefaultConfigFile = "config.yaml"

type Config struct {
	ServerConfig    `yaml:"server"`
	DataStoreConfig `yaml:"dataStore"`
	KeyStoreConfig  `yaml:"keyStore"`
}

type ServerConfig struct {
	HttpConfig         `yaml:"http"`
	HttpsConfig        `yaml:"https"`
	RootInitPubKey     string `yaml:"rootInitPubKey"`
	RootInitPrivateKey string `yaml:"rootInitPriKey"`
}

type HttpConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type HttpsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Port       int    `yaml:"port"`
	CaCert     string `yaml:"caCert"`
	CaKey      string `yaml:"caKey"`
	ServerCert string `yaml:"serverCert"`
	ServerKey  string `yaml:"serverKey"`
}

type DataStoreConfig struct {
	StoreType string `yaml:"type"`
}

type KeyStoreConfig struct {
	StoreType string `yaml:"type"`
}
