// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package config

type ConfigProperty struct {
	Name        string
	Value       string
	Description string
	Sensitive   bool
}

type ConfigItem struct {
	Name       string
	Properties map[string]*ConfigProperty
}
