GOFUMPT ?= go run mvdan.cc/gofumpt@v0.7.0
GOLANGCI ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
SQLC ?= go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
OAPI ?= go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1

.PHONY: build binary deb image smoke smoke-clean generate fmt tidy lint lint-py test integration ci
ci: fmt tidy lint build test

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

build: generate
	go build ./...

test: generate
	go test -race ./...

VERSION ?= 0.0.1
DEB := vulnmanager-ingest_$(VERSION)_amd64.deb
IMAGE ?= vulnmanager/ingest:$(VERSION)

binary: generate
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/ingest .

deb: binary
	mkdir -p dist
	fakeroot debian/rules binary

image:
	docker build -f Dockerfile --build-arg DEB=$(DEB) -t $(IMAGE) dist

smoke:
	docker run -d --name vm-ingest-smoke -p 127.0.0.1:18081:8080 -e INGEST_DATABASE_URL=postgres://smoke@localhost/smoke -e INGEST_TENANT=smoke -e INGEST_RAWSTORE=pg $(IMAGE)
	curl --retry 15 --retry-connrefused --retry-delay 1 -fsS http://127.0.0.1:18081/ping
	curl -fsS -o /dev/null http://127.0.0.1:18081/metrics

smoke-clean:
	docker rm -f vm-ingest-smoke

integration: binary
	python3 -m pytest tests/integration

lint-py:
	python3 -m flake8 tests
