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
	vKeyStoreTestSetup()

	exitCode := m.Run()

	inMemoryKSTestCleanup()
	boltKSTestCleanup()
	vKeyStoreTestCleanup()

	os.Exit(exitCode)
}
