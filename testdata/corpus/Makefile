JUICE_SHOP_VERSION ?= v20.3.0
TRIVY_VERSION ?= 0.75.0
SEMGREP_VERSION ?= 1.180.0
USER_ID := $(shell id -u):$(shell id -g)
TARGET := $(CURDIR)/.cache/juice-shop
LOCK_DIR := $(CURDIR)/targets/juice-shop-$(JUICE_SHOP_VERSION)

.PHONY: all target lockfile trivy semgrep
all: trivy semgrep

target:
	test -d $(TARGET) || git clone --quiet --depth 1 --branch $(JUICE_SHOP_VERSION) https://github.com/juice-shop/juice-shop $(TARGET)

lockfile: target
	mkdir -p $(LOCK_DIR)
	cp $(TARGET)/package.json $(LOCK_DIR)/
	docker run --rm --network host -u $(USER_ID) -e HOME=/tmp -v $(LOCK_DIR):/work -w /work \
		node:22.14.0 npm install --package-lock-only --ignore-scripts --no-audit --no-fund

trivy:
	mkdir -p trivy/$(TRIVY_VERSION)
	docker run --rm --network host -u $(USER_ID) -e TRIVY_CACHE_DIR=/tmp/trivy \
		-v $(LOCK_DIR):/target:ro -v $(CURDIR)/trivy/$(TRIVY_VERSION):/out \
		aquasec/trivy:$(TRIVY_VERSION) fs --no-progress --scanners vuln --format json \
		--output /out/juice-shop.json /target

semgrep: target
	mkdir -p semgrep/$(SEMGREP_VERSION)
	docker run --rm --network host -u $(USER_ID) -e HOME=/tmp -e SEMGREP_SEND_METRICS=off -w /src \
		-v $(TARGET):/src:ro -v $(CURDIR)/rules:/rules:ro -v $(CURDIR)/semgrep/$(SEMGREP_VERSION):/out \
		semgrep/semgrep:$(SEMGREP_VERSION) semgrep scan --config /rules/semgrep.yaml --sarif \
		--output /out/juice-shop.sarif .
