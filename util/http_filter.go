// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package util

import (
	"net/http"
)

// PreHttpHandler processses a request before it gets handed of to the main
// request router and returns the original request or a modified request if
// the next filter in the chain should be invoked; nil otherwise
type PreHttpFilter interface {
	HandlePre(w http.ResponseWriter, r *http.Request) *http.Request
}

// PostHttpFilter processes a response after its request has been processed by
// the main request router and returns true if the next filter in the chain
// should be invoked.
type PostHttpFilter interface {
	HandlePost(w http.ResponseWriter, r *http.Request) bool
}

// HttpFilterManager holds a chain of pre-filters and a chain of post-filters,
// and can be used to build a request/response pipeline from the filters and
// a main handler (see BuildPipeline).
type HttpFilterManager struct {
	preFilters  []PreHttpFilter
	postFilters []PostHttpFilter
}

func NewHttpFilterManager() *HttpFilterManager {
	return &HttpFilterManager{
		preFilters:  make([]PreHttpFilter, 0),
		postFilters: make([]PostHttpFilter, 0),
	}
}

// BuildPipeline builds an returns http.Handler that first invoked the chain of
// pre-handlers, then invokes the provided handler and finally invoked the
// chain of post-handlers in reverse order.
func (fm *HttpFilterManager) BuildPipeline(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextRequest := r
		for _, f := range fm.preFilters {
			nextRequest = f.HandlePre(w, r)
			if nextRequest == nil {
				return
			}
		}

		handler.ServeHTTP(w, nextRequest)

		for i := len(fm.postFilters) - 1; i >= 0; i-- {
			f := fm.postFilters[i]
			if !f.HandlePost(w, r) {
				return
			}
		}
	})
}

func (fm *HttpFilterManager) AddPreFilter(f PreHttpFilter) *HttpFilterManager {
	fm.preFilters = append(fm.preFilters, f)
	return fm
}

func (fm *HttpFilterManager) AddPostFilter(f PostHttpFilter) *HttpFilterManager {
	fm.postFilters = append(fm.postFilters, f)
	return fm
}
