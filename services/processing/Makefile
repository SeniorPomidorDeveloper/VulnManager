GOFUMPT ?= go run mvdan.cc/gofumpt@v0.7.0
GOLANGCI ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
SQLC ?= go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1

.PHONY: build binary deb package image smoke smoke-clean generate fmt tidy lint lint-py test integration ci
ci: fmt tidy lint build test

generate:
	$(MAKE) -C ../../api generate
	$(SQLC) generate

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
DEB := vulnmanager-processing_$(VERSION)_amd64.deb
IMAGE ?= vulnmanager/processing:$(VERSION)

binary: generate
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/processing .

deb: binary package

package:
	mkdir -p dist
	dpkg-buildpackage -b -uc -us -d
	mv ../$(DEB) dist/
	rm -f ../vulnmanager-processing_$(VERSION)_amd64.buildinfo ../vulnmanager-processing_$(VERSION)_amd64.changes

image:
	docker build -f Dockerfile --build-arg DEB=$(DEB) -t $(IMAGE) dist

integration: binary
	python3 -m pytest tests/integration

lint-py:
	python3 -m flake8 tests ../../tests/harness

smoke:
	docker run -d --name vm-processing-smoke -p 127.0.0.1:18083:8082 -e PROCESSING_DATABASE_URL=postgres://smoke@localhost/smoke -e PROCESSING_AMQP_URL=amqp://smoke@localhost:5672/ $(IMAGE)
	curl --retry 15 --retry-connrefused --retry-delay 1 -fsS http://127.0.0.1:18083/ping
	curl -fsS -o /dev/null http://127.0.0.1:18083/metrics

smoke-clean:
	docker rm -f vm-processing-smoke
