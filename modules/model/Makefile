GOFUMPT ?= go run mvdan.cc/gofumpt@v0.7.0
GOLANGCI ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6

.PHONY: fmt tidy lint test ci
ci: fmt tidy lint test

fmt:
	test -z "$$(git ls-files '*.go' | xargs -r $(GOFUMPT) -l)"

tidy:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

lint:
	$(GOLANGCI) run ./...

test:
	go test -race ./...
