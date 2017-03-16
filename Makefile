ARCH := amd64 386
OS := linux darwin windows

TARGET := "vsmd"
DOC := "swagger.json"

PROJECT_DIR := $(shell pwd)
GOPATH := $(abspath $(PROJECT_DIR)/../../../../)
GO_VERSION := "1.8"
PKG_DIR := $(PROJECT_DIR)/pkg
BIN_DIR := $(PROJECT_DIR)/bin
DIST_DIR := $(PROJECT_DIR)/dist

GO_ENV := GOPATH=$(GOPATH)
GO := $(GO_ENV) go

default: check-go-version build

check-go-version:
	if ! go version | grep $(GO_VERSION); then \
		echo "Please make sure you use go $(GO_VERSION)"; \
		exit 1; \
	fi

install-deps:
	$(GO) get -u github.com/satori/go.uuid
	$(GO) get -u github.com/naoina/denco
	$(GO) get -u gopkg.in/yaml.v2
	$(GO) get -u github.com/dgrijalva/jwt-go
	
build: check-go-version fmt vet
	$(GO) build ./...
	$(GO) build -o $(DIST_DIR)/$(TARGET)

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

cross: check-go-version fmt vet
	for os in $(OS); do \
		for arch in $(ARCH); do \
			suffix=""; \
			[ "$${os}" = "windows" ] && suffix=.exe; \
			GOOS=$${os} GOARCH=$${arch} $(GO) build -o "$(DIST_DIR)/$(TARGET)_$${os}_$${arch}{suffix}"; \
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
