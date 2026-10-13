BUF ?= go run github.com/bufbuild/buf/cmd/buf@v1.47.2

.PHONY: generate lint check

generate:
	cd .. && $(BUF) generate

lint:
	cd .. && $(BUF) lint

check: generate
	cd gen/go && go build ./...
