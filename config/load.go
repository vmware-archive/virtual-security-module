// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

import (
	"io/ioutil"
	"gopkg.in/yaml.v2"
)

var DefaultConfigFile = "config.yaml"

func Load(configFile string) (map[string]*ConfigItem, error) {
	buf, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	configItems := make(map[string]*ConfigItem)
	err = yaml.Unmarshal(buf, &configItems)
	if err != nil {
		return nil, err
	}

	return configItems, nil
}

func Save(configItems map[string]*ConfigItem, configFile string) error {
	buf, err := yaml.Marshal(configItems)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(configFile, buf, 0700)
}