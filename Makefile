ARCH := amd64 386
OS := linux darwin windows

TARGET := "vsmd"
DOC := "swagger.json"

CURRENT_DIR := $(shell pwd)
GOPATH := $(abspath $(CURRENT_DIR)/../../../../)
PKG_DIR := $(GOPATH)/pkg
BIN_DIR := $(GOPATH)/bin
DST_DIR := $(GOPATH)/dist

GO_ENV := GOPATH=$(GOPATH)
GO := $(GO_ENV) go

default: build

install-deps:
	$(GO) get -u github.com/satori/go.uuid
	$(GO) get -u github.com/naoina/denco
	$(GO) get -u gopkg.in/yaml.v2
	$(GO) get -u github.com/dgrijalva/jwt-go
	
build: fmt vet
	$(GO) build ./...
	$(GO) build -o $(DST_DIR)/$(TARGET)

vet:
	$(GO) vet .

fmt:
	$(GO) fmt .

cross: fmt vet
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
	rm -rf $(DST_DIR) $(BIN_DIR) $(PKG_DIR)
	rm $(DOC)
