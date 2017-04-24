// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package secret

import (
	"fmt"
	"net/http/httptest"
	"os"

	"github.com/naoina/denco"
)

var ts *httptest.Server

func apiTestSetup() {
	mux := denco.NewMux()
	handlers := sm.RegisterEndpoints(mux)
	handler, err := mux.Build(handlers)
	if err != nil {
		fmt.Printf("Failed to create RESTful API: %v", err)
		os.Exit(1)
	}

	ts = httptest.NewServer(handler)
}

func apiTestCleanup() {
	ts.Close()
}
