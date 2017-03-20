ARCH := amd64 386
OS := linux darwin windows

SERVER_TARGET := vsmd
CLI_TARGET := vsm-cli
DOC := swagger.json

PROJECT_DIR := $(shell pwd)
GOPATH := $(abspath $(PROJECT_DIR)/../../../../)
GO_VERSION := "1.8"
PKG_DIR := $(PROJECT_DIR)/pkg
BIN_DIR := $(PROJECT_DIR)/bin
DIST_DIR := $(PROJECT_DIR)/dist

GO_ENV := GOPATH=$(GOPATH)
GO := $(GO_ENV) go

default: build

install-deps:
	$(GO) get -u github.com/satori/go.uuid
	$(GO) get -u github.com/naoina/denco
	$(GO) get -u gopkg.in/yaml.v2
	$(GO) get -u github.com/dgrijalva/jwt-go
	$(GO) get -u github.com/spf13/cobra/cobra
	
build: fmt vet
	$(GO) build ./...
	$(GO) build -o $(DIST_DIR)/$(SERVER_TARGET) ./server/main
	$(GO) build -o $(DIST_DIR)/$(CLI_TARGET) ./cli/main

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

cross: fmt vet
	for os in $(OS); do \
		for arch in $(ARCH); do \
			suffix=""; \
			[ "$${os}" = "windows" ] && suffix=.exe; \
			GOOS=$${os} GOARCH=$${arch} $(GO) build -o "$(DIST_DIR)/$(SERVER_TARGET)_$${os}_$${arch}{suffix}"; \
		done; \
	done

test:
	$(GO) test ./...

doc:
	swagger generate spec -o ./$(DOC)

doc-serve:
	swagger serve --no-open $(DOC)

clean:
	$(GO) clean .
	rm -rf $(DIST_DIR) $(BIN_DIR) $(PKG_DIR)
