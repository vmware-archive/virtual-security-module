// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package audit

type AuditManager interface {
	Log(msg string)
}