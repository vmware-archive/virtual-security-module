// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

import (
	"os"
	"reflect"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	cfg := GenerateTestConfig()
	cfgFile := "test_config.yaml"
	if err := Save(cfg, cfgFile); err != nil {
		t.Fatalf("Failed to save config file %v: %v", cfgFile, err)
	}
	defer os.Remove(cfgFile)

	cfg2, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Failed to load config file %v: %v", cfgFile, err)
	}

	if !reflect.DeepEqual(cfg, cfg2) {
		t.Fatalf("Saved and loaded configs are different: %v %v", cfg, cfg2)
	}
}