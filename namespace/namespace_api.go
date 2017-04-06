// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

// Package classification Virtual Security Module
//
// Namespace API
//	BasePath: /
//
// swagger:meta
package namespace

import (
	"log"
	"net/http"
	"strings"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

func (namespaceManager *NamespaceManager) RegisterEndpoints(mux *denco.Mux) []denco.Handler {
	// swagger:route POST /namespaces namespaces CreateNamespace
	//
	// Creates a new namespace
	//
	//	Responses:
	//		201: NamespaceCreationResponse
	createNamespace := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		namespaceEntry, err := model.ExtractAndValidateNamespaceEntry(r)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		id, err := namespaceManager.CreateNamespace(r.Context(), namespaceEntry)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if e := util.WriteResponse(w, &model.CreationResponse{Id: id}, http.StatusCreated); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	// swagger:route GET /namespaces* namespaces GetNamespace
	//
	// Retrieves a namespace
	//
	// 	Responses:
	//		200: NamespaceEntryResponse
	getNamespace := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		namespacePath := strings.TrimPrefix(r.URL.Path, "/namespaces")
		if !strings.HasPrefix(namespacePath, "/") {
			namespacePath = "/" + namespacePath
		}

		namespaceEntry, err := namespaceManager.GetNamespace(r.Context(), namespacePath)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if e := util.WriteResponse(w, namespaceEntry, http.StatusOK); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	// swagger:route DELETE /namespaces* namespaces DeleteNamespace
	//
	// Deletes a namespace
	//
	//	Responses:
	//		204
	deleteNamespace := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		namespacePath := strings.TrimPrefix(r.URL.Path, "/namespaces")
		if !strings.HasPrefix(namespacePath, "/") {
			namespacePath = "/" + namespacePath
		}

		err := namespaceManager.DeleteNamespace(r.Context(), namespacePath)
		if err != nil {
			util.WriteErrorStatus(w, err)
			return
		}

		util.WriteStatus(w, http.StatusNoContent)
	}

	handlers := []denco.Handler{
		mux.POST("/namespaces", createNamespace),
		mux.GET("/namespaces*", getNamespace),
		mux.Handler("DELETE", "/namespaces*", deleteNamespace),
	}

	return handlers
}

// swagger:parameters CreateNamespace
type NamespaceEntryParam struct {
	// in:body
	NamespaceEntry model.NamespaceEntry
}

// swagger:response NamespaceCreationResponse
type NamespaceCreationResponse struct {
	// in:body
	Body struct {
		NamespaceId string
	}
}

// swagger:response NamespaceEntryResponse
type NamespaceEntryResponse struct {
	// in:body
	NamespaceEntry model.NamespaceEntry
}
