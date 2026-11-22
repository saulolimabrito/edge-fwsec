# Edge FWSec build entry points. See AGENTS.md.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

GO        ?= go
NPM       ?= npm
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT    ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
# Full commit hash: seeds each binary's GNU build-id (deterministic, traceable).
FULLCOMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo 0)
SHA1      := $(shell command -v sha1sum >/dev/null 2>&1 && echo sha1sum || echo 'shasum -a 1')
# Reproducible builds: the timestamp comes from the last commit, not the clock.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
DATE      := $(shell date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ)
PKG       := github.com/saulolimabrito/edge-fwsec/internal/version
LDFLAGS   := -s -w -buildid= -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)
GOFLAGS_R := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"
CMDS      := efw-web efw-agent efwctl
export SOURCE_DATE_EPOCH
export CGO_ENABLED := 0

.PHONY: all ui ui-deps build linux check test test-go test-race test-ui vet fmt-check repro clean run rpm-src

all: check build

ui-deps:
	cd ui && $(NPM) ci --no-audit --no-fund

ui/node_modules: ui/package-lock.json
	$(MAKE) ui-deps
	touch ui/node_modules

ui: ui/node_modules
	cd ui && $(NPM) run build
	touch ui/dist/.keep

build: ui
	mkdir -p dist/local
	for c in $(CMDS); do $(GO) build $(GOFLAGS_R) -o dist/local/$$c ./cmd/$$c; done

# Appliance targets. The x86_64 baseline is x86-64-v3 (RHEL/Rocky 10 requirement).
linux: ui
	for c in $(CMDS); do \
	  bid=$$(printf '%s %s' "$(FULLCOMMIT)" "$$c" | $(SHA1) | cut -c1-40); \
	  GOOS=linux GOARCH=amd64 GOAMD64=v3 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS) -B 0x$$bid" -o dist/linux-x86_64/$$c ./cmd/$$c; \
	  GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS) -B 0x$$bid" -o dist/linux-aarch64/$$c ./cmd/$$c; \
	done
	cd dist && { command -v sha256sum >/dev/null && sha256sum linux-*/* || shasum -a 256 linux-*/*; } > SHA256SUMS
	cat dist/SHA256SUMS

vet:
	$(GO) vet ./...

fmt-check:
	@out="$$(gofmt -l cmd internal ui/embed.go)"; test -z "$$out" || { echo "gofmt needed: $$out"; exit 1; }

test-go:
	$(GO) test -count=1 ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race -count=2 ./internal/...

test-ui: ui/node_modules
	cd ui && $(NPM) run check && $(NPM) test

test: test-go test-ui

check: fmt-check vet test

# RPM source bundles: reproducible binaries of one architecture + packaging
# files + docs. Version numbers come from RPM_VERSION / the commit.
RPM_VERSION ?= 0.4.0
RPM_RELEASE ?= 0.1.g$(COMMIT)
rpm-src: linux
	for a in x86_64 aarch64; do \
	  d=dist/rpm/edge-fwsec-$(RPM_VERSION); rm -rf $$d; mkdir -p $$d/bin $$d/docs; \
	  cp dist/linux-$$a/* $$d/bin/; cp -R packaging $$d/; cp README.md LICENSE $$d/; \
	  cp docs/architecture.md docs/threat-model.md docs/support-matrix.md $$d/docs/; \
	  (cd dist && { command -v sha256sum >/dev/null && sha256sum linux-$$a/* || shasum -a 256 linux-$$a/*; }) > $$d/SHA256SUMS; \
	  tar --format=ustar -C dist/rpm -czf dist/rpm/edge-fwsec-$(RPM_VERSION)-$$a.tar.gz edge-fwsec-$(RPM_VERSION); \
	done
	rm -rf dist/rpm/edge-fwsec-$(RPM_VERSION)
	cp packaging/rpm/edge-fwsec.spec dist/rpm/
	@echo "rpmbuild -ba --define 'efw_version $(RPM_VERSION)' --define 'efw_release $(RPM_RELEASE)' --define 'efw_commit $(COMMIT)'"

# Build the Linux artefacts twice, from a fresh UI build each time, and compare.
repro:
	$(MAKE) linux >/dev/null
	cp dist/SHA256SUMS dist/SHA256SUMS.first
	rm -rf dist/linux-x86_64 dist/linux-aarch64 ui/dist/assets
	$(MAKE) linux >/dev/null
	diff -u dist/SHA256SUMS.first dist/SHA256SUMS && echo 'reproducible: OK'

# Local stack on https://127.0.0.1:8443 with a fake nft (see scripts/dev.sh).
run: build
	scripts/dev.sh

clean:
	rm -rf dist/local dist/linux-x86_64 dist/linux-aarch64 dist/dev-state ui/dist/assets
	rm -f dist/SHA256SUMS dist/SHA256SUMS.first ui/dist/index.html ui/dist/favicon.svg
