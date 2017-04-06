// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

// Package classification Virtual Security Module
//
// Authorization API
//	BasePath: /
//
// swagger:meta
package authz

import (
	"log"
	"net/http"
	"strings"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
)

func (authzManager *AuthzManager) RegisterEndpoints(mux *denco.Mux) []denco.Handler {
	// swagger:route POST /authz/policies authz-policies CreateAuthzPolicy
	//
	// Creates a new authz policy
	//
	//	Responses:
	//		201: AuthzPolicyCreationResponse
	createAuthzPolicy := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		authzPolicyEntry, err := model.ExtractAndValidateAuthorizationPolicyEntry(r)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		id, err := authzManager.CreatePolicy(r.Context(), authzPolicyEntry)
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

	// swagger:route GET /authz/policies/{path} authz-policies GetAuthzPolicy
	//
	// Returns an authz policy's info
	//
	//	Responses:
	//		200: AuthzPolicyEntryResponse
	getAuthzPolicy := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		policyId := strings.TrimPrefix(r.URL.Path, "/authz/policies/")
		if policyId == "" {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		pe, err := authzManager.GetPolicy(r.Context(), policyId)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if e := util.WriteResponse(w, pe, http.StatusOK); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	// swagger:route DELETE /authz/policies/{path} authz-policies DeleteAuthzPolicy
	//
	// Deletes an authz policy
	//
	//	Responses:
	//		204
	deleteAuthzPolicy := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		policyId := strings.TrimPrefix(r.URL.Path, "/authz/policies/")
		if policyId == "" {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		err := authzManager.DeletePolicy(r.Context(), policyId)
		if err != nil {
			util.WriteErrorStatus(w, err)
			return
		}

		util.WriteStatus(w, http.StatusNoContent)
	}

	handlers := []denco.Handler{
		mux.POST("/authz/policies", createAuthzPolicy),
		mux.GET("/authz/policies/*", getAuthzPolicy),
		mux.Handler("DELETE", "/authz/policies/*", deleteAuthzPolicy),
	}

	return handlers
}

// swagger:parameters CreateAuthzPolicy
type AuthzPolicyEntryParam struct {
	// in:body
	AuthzPolicyEntry model.AuthorizationPolicyEntry
}

// swagger:response AuthzPolicyCreationResponse
type AuthzPolicyCreationResponse struct {
	// in:body
	Body struct {
		AuthzPolicyId string
	}
}

// swagger:response AuthzPolicyEntryResponse
type AuthzPolicyEntryResponse struct {
	// in:body
	AuthzPolicyEntry model.AuthorizationPolicyEntry
}
