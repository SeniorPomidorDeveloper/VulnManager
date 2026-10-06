GOFUMPT ?= go run mvdan.cc/gofumpt@v0.7.0
GOLANGCI ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
SQLC ?= go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
OAPI ?= go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1

.PHONY: generate fmt tidy lint test ci
ci: fmt tidy lint test

generate:
	$(SQLC) generate
	mkdir -p gen/api
	$(OAPI) -config oapi-codegen.yaml ../../api/openapi/ingest.yaml

fmt:
	test -z "$$(git ls-files '*.go' | xargs -r $(GOFUMPT) -l)"

tidy: generate
	go mod tidy
	git diff --exit-code -- go.mod go.sum

lint: generate
	$(GOLANGCI) run ./...

test: generate
	go test -race ./...
