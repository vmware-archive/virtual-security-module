// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

func Load(configFile string) (*Config, error) {
	yamlConfig, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(yamlConfig, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func Save(config *Config, configFile string) error {
	buf, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(configFile, buf, 0700)
}
