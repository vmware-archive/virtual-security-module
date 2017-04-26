ARCH := amd64 386
OS := linux darwin windows

SERVER_TARGET := vsmd
CLI_TARGET := vsm-cli

PROJECT_DIR := $(shell pwd)
GOPATH := $(abspath $(PROJECT_DIR)/../../../../)
GO_VERSION := "1.8"
PKG_DIR := $(PROJECT_DIR)/pkg
BIN_DIR := $(PROJECT_DIR)/bin
DIST_DIR := $(PROJECT_DIR)/dist
DOC_DIR := $(PROJECT_DIR)/doc
DOC := $(DOC_DIR)/swagger.json

GO_ENV := GOPATH=$(GOPATH)
GO_LINT := PATH=${PATH}:$(GOPATH)/bin golint
GO_DEP := PATH=${PATH}:$(GOPATH)/bin godep go
GO := $(GO_ENV) go

ifeq ($(CI),1)
	is_ci = true
else
	is_ci = false
endif

.PHONY: doc

default: build

install-deps:
	$(GO) get -u github.com/golang/lint/golint
	$(GO) get -u github.com/tools/godep

build: fmt vet
	$(GO) build -o $(DIST_DIR)/$(SERVER_TARGET) ./server/main
	$(GO) build -o $(DIST_DIR)/$(CLI_TARGET) ./cli/main

vet:
	$(GO) vet $$($(GO) list ./... | grep -v vendor)

lint:
	for p in $$($(GO) list ./... | grep -v vendor); do \
		if [ $$($(GO_LINT) $${p} | wc -l) != 0 ]; then \
		        if $(is_ci); then \
		                echo "FATAL: you should run 'make lint' on your local system"; \
		                exit 1; \
		        fi; \
		fi; \
	done

fmt:
	if [ $$($(GO) fmt $$($(GO) list ./... | grep -v vendor) | wc -l) != 0 ]; then \
		if $(is_ci); then \
			echo "FATAL: you should run 'make fmt' on your local system"; \
			exit 1; \
		fi; \
	fi

cross: fmt vet
	for os in $(OS); do \
		for arch in $(ARCH); do \
			suffix=""; \
			[ "$${os}" = "windows" ] && suffix=.exe; \
			GOOS=$${os} GOARCH=$${arch} $(GO) build -o "$(DIST_DIR)/$(SERVER_TARGET)_$${os}_$${arch}{suffix}"; \
		done; \
	done

test:
	$(GO) test $$($(GO) list ./... | grep -v vendor)

doc:
	swagger generate spec -o $(DOC) -b ./server/main

doc-serve:
	swagger serve --no-open $(DOC)

clean:
	$(GO) clean .
	rm -rf $(DIST_DIR) $(BIN_DIR) $(PKG_DIR)
