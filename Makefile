setup:
	git config core.hooksPath .githooks

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run ./...

.PHONY: setup build test lint
