// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package server

import (
	"fmt"
	"net/http"

	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/secret"
	"github.com/naoina/denco"
)

type Module interface {
	Type() string
	Init(map[string]*config.ConfigItem) error
	RegisterEndpoints(mux *denco.Mux) []denco.Handler
	Close() error
}

type Server struct {
	modules []Module
	httpServer *http.Server
}

func New() *Server {
	modules := []Module{secret.New()}

	return &Server{
		modules: modules,
		httpServer: nil,
	}
}

func (server *Server) Init(configItems map[string]*config.ConfigItem) error {
	for _, module := range server.modules {
		err := module.Init(configItems)
		if err != nil {
			return err
		}

		fmt.Printf("module %v: initialized\n", module.Type())
	}

	return nil
}

func (server *Server) ListenAndServe(addr string) error {
	mux := denco.NewMux()
	handlers := server.registerEndpoints(mux)
	handler, err := mux.Build(handlers)
	if err != nil {
		return fmt.Errorf("Failed to create RESTful API: %v", err)
	}

	server.httpServer = &http.Server{Addr: addr, Handler: handler}
	fmt.Printf("Listening on %v\n", addr)
	return server.httpServer.ListenAndServe()
}

func (server *Server) registerEndpoints(mux *denco.Mux) []denco.Handler {
	result := []denco.Handler{}

	for _, module := range server.modules {
		handlers := module.RegisterEndpoints(mux)
		result = append(result, handlers...)

		fmt.Printf("module %v: registered handlers\n", module.Type())
	}

	return result
}

func (server *Server) Close() error {
	for _, module := range server.modules {
		if err := module.Close(); err != nil {
			return err
		}
	}

	return nil
}