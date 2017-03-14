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
	"net/http"

	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/naoina/denco"
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
			util.WriteErrorResponse(w, err)
			return
		}

		id, err := secretManager.CreateSecret(secretEntry)
		util.WriteResponse(w, &model.CreationResponse{Id: id}, http.StatusCreated)
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
			util.WriteErrorResponse(w, util.ErrInputValidation)
			return
		}

	    secretEntry, err := secretManager.GetSecret(id)
	    if err != nil {
			util.WriteErrorResponse(w, util.ErrInputValidation)
			return
	    }

	    util.WriteResponse(w, secretEntry, http.StatusOK)
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