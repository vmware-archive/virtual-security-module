// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package model

type CreationResponse struct {
	Id string			`json:"id"`
}

type LoginRequest struct {
	Username string		`json:"username"`
	Challenge string	`json:"challenge"`
}

type ChallengeResponse struct {
	Challenge string	`json:"challenge"`
}