PROFILE ?= core
PROJECT ?= vulnmanager
COMPOSE ?= docker compose -p $(PROJECT) --profile $(PROFILE)
GO_IMAGE ?= golang:1.23.6
GO_CACHE ?= $(HOME)/.cache/vulnmanager-docker-go
GODOCKER = docker run --rm -v $(CURDIR):/src -w /src/$(1) -u $$(id -u):$$(id -g) -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=auto -v $(GO_CACHE)/gopath:/tmp/gopath -v $(GO_CACHE)/gocache:/tmp/gocache $(GO_IMAGE) sh -c 'git config --global --add safe.directory /src && $(2)'
VERSION ?= 0.0.1
IMAGE = docker build -f services/$(1)/Dockerfile --build-arg DEB=vulnmanager-$(1)_$(VERSION)_amd64.deb -t vulnmanager/$(1):$(VERSION) services/$(1)/dist
DEBUILD_IMAGE ?= vulnmanager/debuild:24.04
E2E_IMAGE ?= vulnmanager/e2e:1
E2E = docker run --rm --network $(PROJECT)_default -v $(CURDIR):/src -w /src/tests/e2e -u $$(id -u):$$(id -g) -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 -e E2E_INGEST_URL=http://nginx -e 'E2E_DATABASE_DSN=host=postgres dbname=vulnmanager user=vulnmanager password=vulnmanager-local-dev' $(E2E_IMAGE) sh -c "python -m flake8 . && python -m pytest -o cache_dir=/tmp/pytest"
DEBUILD = docker run --rm -v $(CURDIR)/services/$(1):/w/src -u $$(id -u):$$(id -g) -e HOME=/tmp -w /w/src $(DEBUILD_IMAGE) make package

.PHONY: help go-cache debuild-image e2e-image deb deb-ingest deb-normalize deb-processing image image-ingest image-normalize image-processing build up infra down clean logs ps test test-modules test-services e2e

help:
	@echo "deb       - собрать .deb всех сервисов"
	@echo "image     - собрать образы из готовых .deb"
	@echo "build     - deb + image"
	@echo "up        - собрать и поднять стенд (PROFILE=core|full)"
	@echo "infra     - поднять только PostgreSQL, RabbitMQ и Garage"
	@echo "down      - остановить стенд, данные сохраняются"
	@echo "clean     - остановить стенд и удалить тома"
	@echo "logs      - логи сервисов (SERVICE=<имя> для одного)"
	@echo "ps        - состояние контейнеров"
	@echo "test      - юнит-тесты модулей и сервисов (make ci в каждом)"
	@echo "e2e       - сквозные тесты в контейнере в сети стенда (стенд нужно поднять: make up)"

go-cache:
	mkdir -p $(GO_CACHE)/gopath $(GO_CACHE)/gocache

debuild-image:
	docker build -q -t $(DEBUILD_IMAGE) deploy/local/debuild

deb: deb-ingest deb-normalize deb-processing

deb-ingest: go-cache debuild-image
	$(call GODOCKER,services/ingest,make binary)
	mkdir -p services/ingest/dist
	$(call DEBUILD,ingest)

deb-normalize: go-cache debuild-image
	$(call GODOCKER,services/normalize,make binary)
	mkdir -p services/normalize/dist
	$(call DEBUILD,normalize)

deb-processing: go-cache debuild-image
	$(call GODOCKER,services/processing,make binary)
	mkdir -p services/processing/dist
	$(call DEBUILD,processing)

image: image-ingest image-normalize image-processing

image-ingest:
	$(call IMAGE,ingest)

image-normalize:
	$(call IMAGE,normalize)

image-processing:
	$(call IMAGE,processing)

build: deb image

up: build
	$(COMPOSE) up -d --wait

infra:
	docker compose --profile infra up -d --wait

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f --tail=100 $(SERVICE)

ps:
	$(COMPOSE) ps

test: test-modules test-services

test-modules: go-cache
	$(call GODOCKER,modules/model,make ci)
	$(call GODOCKER,modules/pipeline,make ci)

test-services: go-cache
	$(call GODOCKER,services/ingest,make ci)
	$(call GODOCKER,services/normalize,make ci)
	$(call GODOCKER,services/processing,make ci)

e2e-image:
	docker build -q -t $(E2E_IMAGE) tests/e2e

e2e: e2e-image
	$(E2E)
