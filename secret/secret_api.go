// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

// Package classification Virtual Security Module
//
// Secret Lifecycle Management API
//	BasePath: /
//
// swagger:meta
package secret

import (
	"log"
	"net/http"
	"strings"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

func (secretManager *SecretManager) RegisterEndpoints(mux *denco.Mux) []denco.Handler {
	// swagger:route POST /secrets secrets CreateSecret
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

		id, err := secretManager.CreateSecret(r.Context(), secretEntry)
		if err != nil {
			log.Printf("Error: %s\n", err.Error())
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if e := util.WriteResponse(w, &model.CreationResponse{Id: id}, http.StatusCreated); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	// swagger:route GET /secrets/{path} secrets GetSecret
	//
	// Retrieves a secret
	//
	// 	Responses:
	//		200: SecretEntryResponse
	getSecret := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		secretPath := strings.TrimPrefix(r.URL.Path, "/secrets/")

		if secretPath == "" {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		secretEntry, err := secretManager.GetSecret(r.Context(), secretPath)
		if err != nil {
			log.Printf("Error: %s\n", err.Error())
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if e := util.WriteResponse(w, secretEntry, http.StatusOK); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	// swagger:route DELETE /secrets/{path} secrets DeleteSecret
	//
	// Deletes a secret
	//
	//	Responses:
	//		204
	deleteSecret := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		secretPath := strings.TrimPrefix(r.URL.Path, "/secrets/")

		if secretPath == "" {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if err := secretManager.DeleteSecret(r.Context(), secretPath); err != nil {
			log.Printf("Error: %s\n", err.Error())
			util.WriteErrorStatus(w, err)
			return
		}

		util.WriteStatus(w, http.StatusNoContent)
	}

	handlers := []denco.Handler{
		mux.POST("/secrets", createSecret),
		mux.GET("/secrets/*", getSecret),
		mux.Handler("DELETE", "/secrets/*", deleteSecret),
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
