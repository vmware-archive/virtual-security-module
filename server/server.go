// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/authn"
	"github.com/vmware/virtual-security-module/authz"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/context"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/namespace"
	"github.com/vmware/virtual-security-module/secret"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
)

const (
	DefaultHttpPort            = 8080
	PropertyNameCaCert         = "caCert"
	PropertyNameCaKey          = "caKey"
	PropertyNameServerCert     = "serverCert"
	PropertyNameRootInitPubKey = "rootInitPubKey"
)

type Module interface {
	Type() string
	Init(*context.ModuleInitContext) error
	RegisterEndpoints(mux *denco.Mux) []denco.Handler
	Close() error
}

type TlsConfig struct {
	caCertFile     string
	caKeyFile      string
	serverCertFile string
	serverKeyFile  string
}

type Server struct {
	modules      []Module
	authnManager *authn.AuthnManager
	authzManager *authz.AuthzManager
	httpPipeline http.Handler
	httpServer   *http.Server
	httpsServer  *http.Server
	useHttp      bool
	useHttps     bool
	httpPort     int
	httpsPort    int
	tlsConfig    *TlsConfig
	dataStore    vds.DataStoreAdapter
	keyStore     *vks.VirtualKeyStore
}

func New() *Server {
	authnManager := authn.New()
	authzManager := authz.New()

	modules := []Module{
		authnManager,
		authzManager,
		namespace.New(),
		secret.New(),
	}

	return &Server{
		modules:      modules,
		authnManager: authnManager,
		authzManager: authzManager,
	}
}

func (server *Server) Init(configuration *config.Config) error {
	// data store and key store need to be initialized first, as the modules
	// need them.
	if err := server.initDataStoreFromConfig(configuration); err != nil {
		return err
	}
	if err := server.initKeyStoreFromConfig(configuration); err != nil {
		return err
	}

	// initialize modules
	for _, module := range server.modules {
		moduleInitContext := context.NewModuleInitContext(configuration, server.dataStore, server.keyStore, server.authzManager)
		err := module.Init(moduleInitContext)
		if err != nil {
			return err
		}

		fmt.Printf("module %v: initialized\n", module.Type())
	}

	// initialize rest of server
	if err := server.initSelfFromConfig(configuration); err != nil {
		return err
	}

	return nil
}

func (server *Server) initDataStoreFromConfig(configuration *config.Config) error {
	dsAdapter, err := vds.GetDataStoreFromConfig(configuration)
	if err != nil {
		return err
	}

	server.dataStore = dsAdapter

	return nil
}

func (server *Server) initKeyStoreFromConfig(configuration *config.Config) error {
	vKeyStore, err := vks.GetVirtualKeyStoreFromConfig(configuration)
	if err != nil {
		return err
	}

	server.keyStore = vKeyStore

	return nil
}

func (server *Server) initSelfFromConfig(configuration *config.Config) error {
	server.useHttp = false
	if configuration.HttpConfig.Enabled {
		if err := server.initHttp(configuration); err != nil {
			return err
		}
	}

	server.useHttps = false
	if configuration.HttpsConfig.Enabled {
		if err := server.initHttps(configuration); err != nil {
			return err
		}
	}

	if !server.useHttp && !server.useHttps {
		return fmt.Errorf("http and/or https need to be enabled")
	}

	if server.firstTimeInitRequired() {
		if err := server.firstTimeInit(configuration); err != nil {
			return fmt.Errorf("first time initialization failed: %v", err)
		}
	}

	return nil
}

func (server *Server) firstTimeInitRequired() bool {
	_, err := server.authnManager.GetUser(context.GetSystemRequestContext(), "root")
	return err != nil
}

func (server *Server) firstTimeInit(configuration *config.Config) error {
	if err := server.initRootUser(configuration); err != nil {
		return fmt.Errorf("Failed to initialize root user: %v", err)
	}

	return nil
}

func (server *Server) initHttp(configuration *config.Config) error {
	server.useHttp = true
	if err := util.CheckPort(configuration.HttpConfig.Port); err != nil {
		return err
	}
	server.httpPort = configuration.HttpConfig.Port

	return nil
}

func (server *Server) initHttps(configuration *config.Config) error {
	server.useHttps = true
	if err := util.CheckPort(configuration.HttpsConfig.Port); err != nil {
		return err
	}
	server.httpsPort = configuration.HttpsConfig.Port

	if configuration.HttpsConfig.CaCert == "" {
		return fmt.Errorf("%v cannot be empty", PropertyNameCaCert)
	}
	if configuration.HttpsConfig.CaKey == "" {
		return fmt.Errorf("%v cannot be empty", PropertyNameCaKey)
	}
	if configuration.HttpsConfig.ServerCert == "" {
		return fmt.Errorf("%v cannot be empty", PropertyNameServerCert)
	}
	if configuration.HttpsConfig.ServerCert == "" {
		return fmt.Errorf("%v cannot be empty", PropertyNameServerCert)
	}

	server.tlsConfig = &TlsConfig{
		caCertFile:     configuration.HttpsConfig.CaCert,
		caKeyFile:      configuration.HttpsConfig.CaKey,
		serverCertFile: configuration.HttpsConfig.ServerCert,
		serverKeyFile:  configuration.HttpsConfig.ServerKey,
	}

	return nil
}

func (server *Server) initRootUser(configuration *config.Config) error {
	rootInitPubKey := configuration.ServerConfig.RootInitPubKey
	if rootInitPubKey == "" {
		return fmt.Errorf("%v cannot be empty", PropertyNameRootInitPubKey)
	}

	rsaPubKey, err := util.ReadRSAPublicKey(rootInitPubKey)
	if err != nil {
		return fmt.Errorf("Root initialization failed: %v", err)
	}

	creds, err := json.Marshal(rsaPubKey)
	if err != nil {
		return fmt.Errorf("Root initialization failed: %v", err)
	}

	ue := &model.UserEntry{
		Username:    "root",
		Credentials: creds,
	}

	_, err = server.authnManager.CreateUser(context.GetSystemRequestContext(), ue)

	return err
}

func (server *Server) ListenAndServe() error {
	if err := server.initHttpPipeline(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	if server.useHttp {
		addr := fmt.Sprintf(":%v", server.httpPort)
		server.httpServer = &http.Server{Addr: addr, Handler: server.httpPipeline}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("(http) Listening on %v\n", addr)
			log.Fatal(server.httpServer.ListenAndServe())
		}()
	}

	if server.useHttps {
		addr := fmt.Sprintf(":%v", server.httpsPort)
		server.httpsServer = &http.Server{Addr: addr, Handler: server.httpPipeline}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("(https) Listening on %v\n", addr)
			log.Fatal(server.httpsServer.ListenAndServeTLS(server.tlsConfig.serverCertFile, server.tlsConfig.serverKeyFile))
		}()
	}

	wg.Wait()

	return nil
}

func (server *Server) initHttpPipeline() error {
	mux := denco.NewMux()
	handlers := server.registerEndpoints(mux)
	mainHandler, err := mux.Build(handlers)
	if err != nil {
		return fmt.Errorf("Failed to create RESTful API: %v", err)
	}

	filterManager := util.NewHttpFilterManager()
	filterManager.AddPreFilter(server.authnManager)
	server.httpPipeline = filterManager.BuildPipeline(mainHandler)

	return nil
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
