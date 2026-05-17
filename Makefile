BIN    := cwm-mcp
PKG    := github.com/fractal-manifold/cwm-mcp/cmd/cwm-mcp
PREFIX ?= $(HOME)/.local

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

.PHONY: all build test vet fmt install clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/cwm-mcp

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

install: build
	install -Dm755 $(BIN) $(PREFIX)/bin/$(BIN)
	@echo "Installed to $(PREFIX)/bin/$(BIN)"
	@echo "Register in Claude Code with:"
	@echo "    claude mcp add cwm-mcp -- $(PREFIX)/bin/$(BIN)"

clean:
	rm -f $(BIN)
