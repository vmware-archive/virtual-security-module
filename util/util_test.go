// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package util

import (
	"testing"
)

func TestCheckPort(t *testing.T) {
	negativePort := -1
	overlapPort := 80000
	normalPort := 443

	if err := CheckPort(negativePort); err == nil {
		t.Fatalf("Failed on port check. Port: %v", negativePort)
	}
	if err := CheckPort(overlapPort); err == nil {
		t.Fatalf("Failed on port check. Port: %v", overlapPort)
	}
	if err := CheckPort(normalPort); err != nil {
		t.Fatalf("Failed on port check. Port: %v", negativePort)
	}
}
