.PHONY: all build build-cli build-daemon clean test lint run-daemon install

# Build variables
VERSION ?= 0.1.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

# Output directories
BIN_DIR := bin
DIST_DIR := dist

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Default target
all: build

# Build all binaries
build: build-cli build-daemon

# Build CLI
build-cli:
	@echo "Building ninjashield CLI..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/ninjashield ./cmd/ninjashield

# Build daemon
build-daemon:
	@echo "Building ninjashieldd daemon..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/ninjashieldd ./cmd/ninjashieldd

# Run daemon for development
run-daemon: build-daemon
	./$(BIN_DIR)/ninjashieldd

# Run tests
test:
	$(GOTEST) -v -race -cover ./...

# Run tests with coverage report
test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Lint code
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

# Tidy dependencies
tidy:
	$(GOMOD) tidy

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR) $(DIST_DIR)
	@rm -f coverage.out coverage.html

# Install binaries to GOPATH/bin
install: build
	@echo "Installing to $(GOPATH)/bin..."
	@cp $(BIN_DIR)/ninjashield $(GOPATH)/bin/
	@cp $(BIN_DIR)/ninjashieldd $(GOPATH)/bin/

# Cross-platform builds
build-all: build-linux build-darwin build-windows

build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(DIST_DIR)/linux-amd64
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/linux-amd64/ninjashield ./cmd/ninjashield
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/linux-amd64/ninjashieldd ./cmd/ninjashieldd
	@mkdir -p $(DIST_DIR)/linux-arm64
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/linux-arm64/ninjashield ./cmd/ninjashield
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/linux-arm64/ninjashieldd ./cmd/ninjashieldd

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(DIST_DIR)/darwin-amd64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/darwin-amd64/ninjashield ./cmd/ninjashield
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/darwin-amd64/ninjashieldd ./cmd/ninjashieldd
	@mkdir -p $(DIST_DIR)/darwin-arm64
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/darwin-arm64/ninjashield ./cmd/ninjashield
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/darwin-arm64/ninjashieldd ./cmd/ninjashieldd

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(DIST_DIR)/windows-amd64
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/windows-amd64/ninjashield.exe ./cmd/ninjashield
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/windows-amd64/ninjashieldd.exe ./cmd/ninjashieldd

# Show help
help:
	@echo "NinjaShield Build Targets:"
	@echo "  make build        - Build CLI and daemon for current platform"
	@echo "  make build-cli    - Build only the CLI"
	@echo "  make build-daemon - Build only the daemon"
	@echo "  make run-daemon   - Build and run the daemon"
	@echo "  make test         - Run tests"
	@echo "  make test-coverage- Run tests with coverage report"
	@echo "  make lint         - Run linter"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make install      - Install binaries to GOPATH/bin"
	@echo "  make build-all    - Build for all platforms"
	@echo "  make tidy         - Tidy go.mod"
