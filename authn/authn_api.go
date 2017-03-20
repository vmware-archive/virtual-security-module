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
	"log"
	"net/http"

	"github.com/naoina/denco"
	"github.com/vmware/virtual-security-module/model"
	"github.com/vmware/virtual-security-module/util"
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
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		id, err := authnManager.CreateUser(userEntry)
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

	// swagger:route GET /users/{username} users GetUser
	//
	// Returns a user's info
	//
	//	Responses:
	//		200: UserEntryResponse
	getUser := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		username := params.Get("username")
		if username == "" {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		ue, err := authnManager.GetUser(username)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		if e := util.WriteResponse(w, ue, http.StatusOK); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
	}

	// swagger:route DELETE /users/{username} users DeleteUser
	//
	// Deletes a user
	//
	//	Responses:
	//		204
	deleteUser := func(w http.ResponseWriter, r *http.Request, params denco.Params) {
		username := params.Get("username")
		if username == "" {
			if e := util.WriteErrorResponse(w, util.ErrInputValidation); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		err := authnManager.DeleteUser(username)
		if err != nil {
			util.WriteErrorStatus(w, err)
			return
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
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		challengeOrToken, err := authnManager.Login(loginRequest)
		if err != nil {
			if e := util.WriteErrorResponse(w, err); e != nil {
				log.Printf("failed to write error response: %v\n", e)
			}
			return
		}

		loginResponse := &model.LoginResponse{
			ChallengeOrToken: challengeOrToken,
		}
		if e := util.WriteResponse(w, loginResponse, http.StatusOK); e != nil {
			log.Printf("failed to write response: %v\n", e)
		}
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
