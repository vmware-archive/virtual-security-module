// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/vmware/virtual-security-module/authn"
	"github.com/vmware/virtual-security-module/config"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/secret"
	"github.com/vmware/virtual-security-module/util"
	"github.com/vmware/virtual-security-module/vds"
	"github.com/vmware/virtual-security-module/vks"
	"github.com/naoina/denco"
)

const (
	PropertyNameServer = "server"
	PropertyNameHttp = "http";
	PropertyNameHttps = "https";
	PropertyNameCACert = "caCert";
	PropertyNameCAKey = "caKey";
	PropertyNameServerCert = "serverCert";
	PropertyNameServerKey = "serverKey";
	PropertyNameHttpPort = "httpPort";
	PropertyNameHttpsPort = "httpsPort";
	PropertyNameRootInitPubKey = "rootInitPubKey"
	
	DefaultHttpPort = 8080
	DefaultHttpsPort = 443
)

type Module interface {
	Type() string
	Init(map[string]*config.ConfigItem, vds.DataStoreAdapter, vks.KeyStoreAdapter) error
	RegisterEndpoints(mux *denco.Mux) []denco.Handler
	Close() error
}

type TlsConfig struct {
	caCertFile string
	caKeyFile string
	serverCertFile string
	serverKeyFile string	
}

type Server struct {
	modules []Module
	authnManager *authn.AuthnManager
	httpPipeline http.Handler
	httpServer *http.Server
	httpsServer *http.Server
	useHttp bool
	useHttps bool
	httpPort int
	httpsPort int
	tlsConfig *TlsConfig
	dataStore vds.DataStoreAdapter
	keyStore vks.KeyStoreAdapter
}

func New() *Server {
	authnManager := authn.New()
	modules := []Module{
		secret.New(),
		authnManager,
	}

	return &Server{
		modules: modules,
		authnManager: authnManager,
	}
}

func (server *Server) Init(configItems map[string]*config.ConfigItem) error {
	// data store and key store need to be initialized first, as the modules
	// need them.
	if err := server.initDataStoreFromConfig(configItems); err != nil {
		return err
	}
	if err := server.initKeyStoreFromConfig(configItems); err != nil {
		return err
	}
	
	// initialize modules
	for _, module := range server.modules {
		err := module.Init(configItems, server.dataStore, server.keyStore)
		if err != nil {
			return err
		}

		fmt.Printf("module %v: initialized\n", module.Type())
	}
	
	// initialize rest of server
	if err:= server.initSelfFromConfig(configItems); err != nil {
		return err
	}

	return nil
}

func (server *Server) initDataStoreFromConfig(configItems map[string]*config.ConfigItem) error {
	dsAdapter, err := vds.GetDataStoreFromConfig(configItems)
	if err != nil {
		return err
	}
	
	server.dataStore = dsAdapter

	return nil
}

func (server *Server) initKeyStoreFromConfig(configItems map[string]*config.ConfigItem) error {
	ksAdapter, err := vks.GetKeyStoreFromConfig(configItems)
	if err != nil {
		return err
	}
	
	server.keyStore = ksAdapter

	return nil
}

func (server *Server) initSelfFromConfig(configItems map[string]*config.ConfigItem) error {
	serverConfigItem, ok := configItems[PropertyNameServer]
	if !ok {
		return fmt.Errorf("Mandatory config item %v is missing in config", PropertyNameServer)
	}
	
	var err error
	useHttp := false
	httpProperty, ok := serverConfigItem.Properties[PropertyNameHttp]
	if ok {
		useHttp, err = strconv.ParseBool(httpProperty.Value)
		if err != nil {
			return fmt.Errorf("Failed to parse config property %v: %v", PropertyNameHttp, err)
		}
		server.useHttp = useHttp
		if useHttp {
			httpPortProperty, ok := serverConfigItem.Properties[PropertyNameHttpPort]
			server.httpPort = DefaultHttpPort
			if ok {
				httpPort, err := strconv.Atoi(httpPortProperty.Value)
				if err != nil {
					return fmt.Errorf("Failed to parse config property %v: %v", PropertyNameHttpPort, err)
				}
				server.httpPort = httpPort
			}
		}
	}
	
	useHttps := false
	httpsProperty, ok := serverConfigItem.Properties[PropertyNameHttps]
	if ok {
		useHttps, err = strconv.ParseBool(httpsProperty.Value)
		if err != nil {
			return fmt.Errorf("Failed to parse config property %v: %v", PropertyNameHttps, err)
		}
		server.useHttps = useHttps
		if useHttps {
			httpsPortProperty, ok := serverConfigItem.Properties[PropertyNameHttpsPort]
			server.httpsPort = DefaultHttpsPort
			if ok {
				httpsPort, err := strconv.Atoi(httpsPortProperty.Value)
				if err != nil {
					return fmt.Errorf("Failed to parse config property %v: %v", PropertyNameHttpsPort, err)
				}
				server.httpsPort = httpsPort
			}
		}	
	}
	
	if !useHttp && !useHttps {
		return fmt.Errorf("http and/or https need to be enabled")
	}
	
	if useHttps {
		caCertProperty, ok := serverConfigItem.Properties[PropertyNameCACert]
		if !ok {
			return fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameCACert)
		}
		caKeyProperty, ok := serverConfigItem.Properties[PropertyNameCAKey]
		if !ok {
			return fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameCAKey)
		}
		serverCertProperty, ok := serverConfigItem.Properties[PropertyNameServerCert]
		if !ok {
			return fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameServerCert)
		}
		serverKeyProperty, ok := serverConfigItem.Properties[PropertyNameServerKey]
		if !ok {
			return fmt.Errorf("Mandatory config property %v is missing in config", PropertyNameServerKey)
		}
		
		server.tlsConfig = &TlsConfig{
			caCertFile: caCertProperty.Value,
			caKeyFile: caKeyProperty.Value,
			serverCertFile: serverCertProperty.Value,
			serverKeyFile: serverKeyProperty.Value, 
		}	
	}
	
	if _, err := server.authnManager.GetUser("root"); err != nil {
		rootInitPubKeyProperty, ok := serverConfigItem.Properties[PropertyNameRootInitPubKey]
		if !ok {
			return fmt.Errorf("Mandatory config property for root initialization %v is missing in config", PropertyNameRootInitPubKey)
		}
		if e := server.initRootUser(rootInitPubKeyProperty); e != nil {
			return fmt.Errorf("Failed to initialize root user: %v", e)
		}
	}

	return nil
}

func (server *Server) initRootUser(rootInitPubKeyProperty *config.ConfigProperty) error {
	rsaPubKey, err := util.ReadRSAPublicKey(rootInitPubKeyProperty.Value)
	if err != nil {
		return fmt.Errorf("Root initialization failed: %v", err)
	}
	
	creds, err := json.Marshal(rsaPubKey)
	if err != nil {
		return fmt.Errorf("Root initialization failed: %v", err)
	}

	ue := &model.UserEntry{
		Username: "root",
		Credentials: creds,
	}

	_, err = server.authnManager.CreateUser(ue)
	
	return err
}

func (server *Server) ListenAndServe() error {
	if err := server.initHttpPipeline(); err != nil {
		return err
	}
	
	var wg sync.WaitGroup
	if (server.useHttp) {
		addr := fmt.Sprintf(":%v", server.httpPort)
		server.httpServer = &http.Server{Addr: addr, Handler: server.httpPipeline}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("Listening on %v\n", addr)
			log.Fatal(server.httpServer.ListenAndServe())
		}()
	}
	
	if (server.useHttps) {
		addr := fmt.Sprintf(":%v", server.httpsPort)
		server.httpsServer = &http.Server{Addr: addr, Handler: server.httpPipeline}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("Listening on %v\n", addr)
			log.Fatal(server.httpsServer.ListenAndServeTLS(server.tlsConfig.caCertFile, server.tlsConfig.caKeyFile))
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