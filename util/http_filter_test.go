// Copyright © 2017 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause
package util

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var mainHandlerSet bool = false
var counter int = 0

func TestJustHandler(t *testing.T) {
	fm := NewHttpFilterManager()
	pipeline := fm.BuildPipeline(getMainHandler())
	excercisePipeline(pipeline)
	if !testMainHandlerSet() {
		t.Fatalf("main handler expected to be invoked")
	}
}

func TestPreDropper(t *testing.T) {
	fm := NewHttpFilterManager()
	pipeline := fm.AddPreFilter(getPreDropper()).BuildPipeline(getMainHandler())
	excercisePipeline(pipeline)
	if testMainHandlerSet() {
		t.Fatalf("main handler not expected to be invoked")
	}
}

func TestPostDropper(t *testing.T) {
	fm := NewHttpFilterManager()
	pipeline := fm.AddPostFilter(getPostDropper()).BuildPipeline(getMainHandler())
	excercisePipeline(pipeline)
	if !testMainHandlerSet() {
		t.Fatalf("main handler expected to be invoked")
	}
}

func TestOppositePrePost(t *testing.T) {
	fm := NewHttpFilterManager()
	for i := 1; i < 4; i++ {
		f := getOppositePrePost(i)
		fm.AddPreFilter(f)
		fm.AddPostFilter(f)
	}
	pipeline := fm.BuildPipeline(getMainHandler())
	excercisePipeline(pipeline)
	if !testCounterZero() {
		t.Fatalf("counter expected to be zero")
	}

}

func testMainHandlerSet() bool {
	return mainHandlerSet
}

func testCounterZero() bool {
	return counter == 0
}

func getMainHandler() http.Handler {
	mainHandlerSet = false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mainHandlerSet = true
	})
}

type httpFilterHelper struct {
	preFunc  func(w http.ResponseWriter, r *http.Request) bool
	postFunc func(w http.ResponseWriter, r *http.Request) bool
}

func (fh *httpFilterHelper) HandlePre(w http.ResponseWriter, r *http.Request) bool {
	return fh.preFunc(w, r)
}

func (fh *httpFilterHelper) HandlePost(w http.ResponseWriter, r *http.Request) bool {
	return fh.postFunc(w, r)
}

func getPreDropper() PreHttpFilter {
	return &httpFilterHelper{
		preFunc: func(w http.ResponseWriter, r *http.Request) bool {
			return false
		},
		postFunc: nil,
	}
}

func getPostDropper() PostHttpFilter {
	return &httpFilterHelper{
		preFunc: nil,
		postFunc: func(w http.ResponseWriter, r *http.Request) bool {
			return false
		},
	}
}

func getOppositePrePost(amount int) *httpFilterHelper {
	return &httpFilterHelper{
		preFunc: func(w http.ResponseWriter, r *http.Request) bool {
			counter += amount
			return true
		},
		postFunc: func(w http.ResponseWriter, r *http.Request) bool {
			counter -= amount
			return true
		},
	}
}

func excercisePipeline(pipeline http.Handler) {
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	pipeline.ServeHTTP(w, r)
}
