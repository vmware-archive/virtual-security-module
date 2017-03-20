// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"fmt"
	"log"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/server"
)

func main() {
	// load config
	cfg, err := config.Load(config.DefaultConfigFile)
	if err != nil {
		fmt.Printf("Failed to load config file: %v: %v\n", config.DefaultConfigFile, err)
		return
	}

	// instantiate server and init using config
	server := server.New()
	if err := server.Init(cfg); err != nil {
		fmt.Printf("Failed to initialize server: %v\n", err)
		return
	}
	defer server.Close()

	// create RESTful api surface and listen
	log.Fatal(server.ListenAndServe())
}
