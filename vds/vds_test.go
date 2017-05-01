// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vds

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	inMemoryDSTestSetup()

	exitCode := m.Run()

	inMemoryDSTestCleanup()

	os.Exit(exitCode)
}
