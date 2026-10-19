GOFUMPT ?= go run mvdan.cc/gofumpt@v0.7.0
GOLANGCI ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
SQLC ?= go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
RABBITMQ_IMAGE ?= rabbitmq:3.13.7-alpine
COMPOSE ?= docker compose -f ../../docker-compose.yaml --profile core
RABBIT_API ?= http://vulnmanager:vulnmanager-local-dev@127.0.0.1:15672/api
OAPI ?= go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1

.PHONY: build binary deb package image smoke smoke-clean compose-check compose-clean generate fmt tidy lint lint-py test integration ci
ci: fmt tidy lint build test

generate:
	$(MAKE) -C ../../api generate
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

deb: binary package

package:
	mkdir -p dist
	dpkg-buildpackage -b -uc -us -d
	mv ../$(DEB) dist/
	rm -f ../vulnmanager-ingest_$(VERSION)_amd64.buildinfo ../vulnmanager-ingest_$(VERSION)_amd64.changes

image:
	docker build -f Dockerfile --build-arg DEB=$(DEB) -t $(IMAGE) dist

smoke:
	docker network create vm-ingest-smoke
	docker run -d --name vm-ingest-smoke-rabbitmq --network vm-ingest-smoke -v $(abspath ../../tests/harness/enabled_plugins):/etc/rabbitmq/enabled_plugins:ro $(RABBITMQ_IMAGE)
	docker run -d --name vm-ingest-smoke --network vm-ingest-smoke --restart on-failure -p 127.0.0.1:18081:8080 -e INGEST_DATABASE_URL=postgres://smoke@localhost/smoke -e INGEST_TENANT=smoke -e INGEST_RAWSTORE=pg -e INGEST_AMQP_URL=amqp://guest:guest@vm-ingest-smoke-rabbitmq:5672/ $(IMAGE)
	curl --retry 30 --retry-all-errors --retry-delay 2 -fsS http://127.0.0.1:18081/ping
	curl -fsS -o /dev/null http://127.0.0.1:18081/metrics

smoke-clean:
	docker rm -f vm-ingest-smoke vm-ingest-smoke-rabbitmq
	-docker network rm vm-ingest-smoke

compose-check:
	$(COMPOSE) up -d --build --wait ingest
	curl -fsS -X PUT -H 'content-type: application/json' -d '{"durable":true}' $(RABBIT_API)/queues/%2F/ci-sink
	curl -fsS -X POST -H 'content-type: application/json' -d '{"routing_key":"1"}' $(RABBIT_API)/bindings/%2F/e/vulnmanager.report.received/q/ci-sink
	curl -fsS -X POST http://127.0.0.1:8080/api/v1/reports -H 'X-Tool: trivy' -H 'X-Scope: ci/main' --data-binary 'report'

compose-clean:
	$(COMPOSE) down -v

integration: binary
	python3 -m pytest tests/integration

lint-py:
	python3 -m flake8 tests ../../tests/harness
