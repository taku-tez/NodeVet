BINARY_NAME := nodevet
BUILD_DIR   := bin

.PHONY: build test lint vet fmt clean ci

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/nodevet/...

test:
	go test -race -cover ./...

test-verbose:
	go test -race -cover -v ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

ci: vet test build
