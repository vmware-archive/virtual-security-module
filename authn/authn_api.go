// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

// Package classification Authentication API
//
// User Management and Authentication API
//	BasePath: /
//
// swagger:meta
package authn

import (
	"fmt"
	"net/http"

	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
	"github.com/naoina/denco"
)

func (authnManager *AuthnManager) RegisterEndpoints(mux *denco.Mux) []denco.Handler {
	// swagger:route POST /users users CreateUser
	//
	// Creates a new user
	//
	//	Responses:
	//		201: UserCreationResponse
	createUser := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		userEntry, err := model.ExtractAndValidateUserEntry(r)
		if err != nil {
			util.WriteErrorResponse(w, err, http.StatusBadRequest)
			return
		}

		id, err := authnManager.CreateUser(userEntry)
		util.WriteResponse(w, &model.CreationResponse{Id: id}, http.StatusCreated)
	}

	// swagger:route POST /login users Login
	//
	// Retrieves a secret
	//
	// 	Responses:
	//		200: LoginResponse
	login := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		loginRequest, err := model.ExtractAndValidateLoginRequest(r)
		if err != nil {
			util.WriteErrorResponse(w, err, http.StatusBadRequest)
			return
		}

	    challenge, err := authnManager.Login(loginRequest)
	    if err != nil {
			util.WriteResponse(w, fmt.Errorf("login failed: %v", err), http.StatusForbidden)
			return
	    }

		challengeResponse := &model.ChallengeResponse {
			Challenge: challenge,
		}
	    util.WriteResponse(w, challengeResponse, http.StatusOK)
	}

	handlers := []denco.Handler{
        mux.POST("/users", createUser),
        mux.POST("/login", login),
    }

	return handlers
}

// swagger:parameters CreateUser
type UserEntryParam struct {
	// in:body
	UserEntry model.UserEntry
}

// swagger:response UserCreationResponse
type UserCreationResponse struct {
	// in:body
	Body struct {
		UserId string
	}
}

// swagger:response LoginResponse
type LoginResponse struct {
	// in:body
	ChallengeResponse model.ChallengeResponse
}