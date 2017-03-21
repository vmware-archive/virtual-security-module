// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

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
	Cert  string = ""
)

func init() {
	RootCmd.PersistentFlags().StringVarP(&Url, "url", "u", fmt.Sprintf("http://localhost:%v", server.DefaultHttpPort), "server URL")
	RootCmd.PersistentFlags().StringVarP(&Token, "token", "t", "", "auth token")
	RootCmd.PersistentFlags().StringVarP(&Cert, "cert", "c", "certs/test-root-cert.pem", "root CA certificate filename")
}

func httpClient() (*http.Client, error) {
	u, err := url.Parse(Url)
	if err != nil {
		return nil, err
	}

	if strings.EqualFold(u.Scheme, "https") {
		rootCertPEM, err := ioutil.ReadFile(Cert)
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(rootCertPEM)
		if !ok {
			return nil, fmt.Errorf("failed to add certificate from %v to trust chain", Cert)
		}

		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: certPool},
			},
		}, nil
	}

	return http.DefaultClient, nil
}
