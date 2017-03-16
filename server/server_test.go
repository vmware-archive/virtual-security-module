// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package server

import (
	"fmt"
	"testing"
	"os"
	
	"github.com/vmware/virtual-security-module/config"
)

var s *Server
var tCfg map[string]*config.ConfigItem

func TestMain(m *testing.M) {
	tCfg = config.GenerateTestConfig()
	
	s = New()
	if err := s.Init(tCfg); err != nil {
		fmt.Printf("Failed to initialize server: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	apiTestSetup()
	defer apiTestCleanup()
	
	os.Exit(m.Run())
}