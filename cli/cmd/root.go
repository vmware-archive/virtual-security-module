// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vmware/virtual-security-module/server"
)

var (
	RootCmd = &cobra.Command{
		Use:   "vsm-cli",
		Short: "A command-line interface client for vsm",
		Long: `A command-line interface client for the vsm (Virtual Security Module) server.
For more information visit https://github.com/vmware/virtual-security-module.`,
	}
	Url   string = ""
	Token string = ""
)

func init() {
	RootCmd.PersistentFlags().StringVarP(&Url, "url", "u", fmt.Sprintf("http://localhost:%v", server.DefaultHttpPort), "server URL")
	RootCmd.PersistentFlags().StringVarP(&Token, "token", "t", "", "auth token")
}
