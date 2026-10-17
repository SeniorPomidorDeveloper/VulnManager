PROFILE ?= core
HOSTNET ?=
COMPOSE ?= docker compose $(if $(HOSTNET),-f docker-compose.yaml -f deploy/local/compose.host-network.yaml) --profile $(PROFILE)
GO_IMAGE ?= golang:1.23.6
GO_CACHE ?= $(HOME)/.cache/vulnmanager-docker-go
GODOCKER = docker run --rm --network host -v $(CURDIR):/src -w /src/$(1) -u $$(id -u):$$(id -g) -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=auto -v $(GO_CACHE)/gopath:/tmp/gopath -v $(GO_CACHE)/gocache:/tmp/gocache $(GO_IMAGE) sh -c 'git config --global --add safe.directory /src && $(2)'
VERSION ?= 0.0.1
IMAGE = docker build --network host -f services/$(1)/Dockerfile --build-arg DEB=vulnmanager-$(1)_$(VERSION)_amd64.deb -t vulnmanager/$(1):$(VERSION) services/$(1)/dist
DEBUILD_IMAGE ?= vulnmanager/debuild:24.04
DEBUILD = docker run --rm -v $(CURDIR)/services/$(1):/w -u $$(id -u):$$(id -g) -e HOME=/tmp -w /w $(DEBUILD_IMAGE) sh -c 'debian/rules clean && fakeroot debian/rules binary'

.PHONY: help go-cache debuild-image deb deb-ingest deb-normalize deb-processing image image-ingest image-normalize image-processing build up infra down clean logs ps test test-modules test-services e2e

help:
	@echo "deb       - собрать .deb всех сервисов"
	@echo "image     - собрать образы из готовых .deb"
	@echo "build     - deb + image"
	@echo "up        - собрать и поднять стенд (PROFILE=core|full; HOSTNET=1 - сеть хоста, если мосты Docker не работают)"
	@echo "infra     - поднять только PostgreSQL, RabbitMQ и Garage"
	@echo "down      - остановить стенд, данные сохраняются"
	@echo "clean     - остановить стенд и удалить тома"
	@echo "logs      - логи сервисов (SERVICE=<имя> для одного)"
	@echo "ps        - состояние контейнеров"
	@echo "test      - юнит-тесты модулей и сервисов (make ci в каждом)"
	@echo "e2e       - сквозные тесты против поднятого стенда"

go-cache:
	mkdir -p $(GO_CACHE)/gopath $(GO_CACHE)/gocache

debuild-image:
	docker build --network host -q -t $(DEBUILD_IMAGE) deploy/local/debuild

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

e2e:
	$(MAKE) -C tests/e2e ci
