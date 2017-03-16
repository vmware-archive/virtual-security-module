// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

// Package classification Secret Management API
//
// Secret Lifecycle Management API
//	BasePath: /secrets
//
// swagger:meta
package secret

import (
	"log"
	"net/http"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

func (secretManager *SecretManager) RegisterEndpoints(mux *denco.Mux) []denco.Handler {
	// swagger:route POST / secrets CreateSecret
	//
	// Creates a new secret
	//
	//	Responses:
	//		201: SecretCreationResponse
	createSecret := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		secretEntry, err := model.ExtractAndValidateSecretEntry(r)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		id, err := secretManager.CreateSecret(secretEntry)
		if e := util.WriteResponse(w, &model.CreationResponse{Id: id}, http.StatusCreated); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	// swagger:route GET /{id} secrets GetSecret
	//
	// Retrieves a secret
	//
	// 	Responses:
	//		200: SecretEntryResponse
	getSecret := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		id := params.Get("id")
		if id == "" {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		secretEntry, err := secretManager.GetSecret(id)
		if err != nil {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if e := util.WriteResponse(w, secretEntry, http.StatusOK); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	handlers := []denco.Handler{
		mux.POST("/secrets", createSecret),
		mux.GET("/secrets/:id", getSecret),
	}

	return handlers
}

// swagger:parameters CreateSecret
type SecretEntryParam struct {
	// in:body
	SecretEntry model.SecretEntry
}

// swagger:response SecretCreationResponse
type SecretCreationResponse struct {
	// in:body
	Body struct {
		SecretId string
	}
}

// swagger:response SecretEntryResponse
type SecretEntryResponse struct {
	// in:body
	SecretEntry model.SecretEntry
}
