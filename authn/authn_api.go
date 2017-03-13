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
			util.WriteErrorResponse(w, err)
			return
		}

		id, err := authnManager.CreateUser(userEntry)
		if err != nil {
			util.WriteErrorResponse(w, err)	
		}
		
		util.WriteResponse(w, &model.CreationResponse{Id: id}, http.StatusCreated)
	}
	
	// swagger:route GET /users/{username} users GetUser
	//
	// Returns a user's info
	//
	//	Responses:
	//		200: UserEntryResponse
	getUser := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		username := params.Get("username")
		if username == "" {
			util.WriteErrorResponse(w, util.ErrInputValidation)
			return
		}

		ue, err := authnManager.GetUser(username)
		if err != nil {
			util.WriteErrorResponse(w, err)	
		}
		
		util.WriteResponse(w, ue, http.StatusOK)
	}
	
	// swagger:route DELETE /users/{username} users CreateUser
	//
	// Deletes a user
	//
	//	Responses:
	//		204
	deleteUser := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		username := params.Get("username")
		if username == "" {
			util.WriteErrorResponse(w, util.ErrInputValidation)
			return
		}

		err := authnManager.DeleteUser(username)
		if err != nil {
			util.WriteErrorStatus(w, err)	
		}
		
		util.WriteStatus(w, http.StatusNoContent)
	}

	// swagger:route POST /login users Login
	//
	// Log-in. Expected to be invoked twice by a client:
	//     First phase: client provides the username and gets back a challenge,
	//          decrypted by the user's public key
	//     Second phase: client decrypts the challenge with the user's private
	//          key and provides it with the request; and gets a token
	//
	// 	Responses:
	//		200: LoginResp
	login := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		loginRequest, err := model.ExtractAndValidateLoginRequest(r)
		if err != nil {
			util.WriteErrorResponse(w, err)
			return
		}

	    challengeOrToken, err := authnManager.Login(loginRequest)
	    if err != nil {
			util.WriteErrorResponse(w, err)
			return
	    }

		loginResponse := &model.LoginResponse {
			ChallengeOrToken: challengeOrToken,
		}
	    util.WriteResponse(w, loginResponse, http.StatusOK)
	}

	handlers := []denco.Handler{
        mux.POST("/users", createUser),
        mux.GET("/users/:username", getUser),
        mux.Handler("DELETE", "/users/:username", deleteUser),
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

// swagger:response UserEntryResponse
type UserEntryResponse struct {
	// in:body
	UserEntry model.UserEntry
}

// swagger:response LoginResp
type LoginResp struct {
	// in:body
	LoginResp model.LoginResponse
}