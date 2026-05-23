BIN    := cwm-mcp-go
PKG    := github.com/fractal-manifold/cwm-mcp/cmd/cwm-mcp
PREFIX ?= $(HOME)/.local

# Version comes from the repository-root VERSION file (single source of
# truth shared by the Go, Python and JS impls); the git describe is kept
# as a fallback so dev builds still get something meaningful.
VERSION_FILE := $(realpath $(CURDIR)/../VERSION)
VERSION := $(shell cat $(VERSION_FILE) 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
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
	@echo "Now install the launcher so Claude Code can find it:"
	@echo "    sh ../cwm-mcp-launcher/install.sh"
	@echo "(The launcher exposes 'cwm-mcp' on PATH and picks Go/Python/JS"
	@echo " in priority order.)"

clean:
	rm -f $(BIN)
