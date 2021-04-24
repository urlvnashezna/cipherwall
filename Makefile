GO ?= go

.PHONY: build test lint install clean

build:
	$(GO) build -o bin/cipherwall ./cmd/cipherwall

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

install:
	$(GO) install ./cmd/cipherwall

clean:
	rm -rf bin coverage.out
