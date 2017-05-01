// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package vks

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	inMemoryKSTestSetup()
	boltKSTestSetup()

	exitCode := m.Run()

	inMemoryKSTestCleanup()
	boltKSTestCleanup()

	os.Exit(exitCode)
}
