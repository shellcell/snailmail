# Build and release targets for snailmail.
#
# CI calls these rather than carrying its own copies of the commands, so a
# release built on a runner is built the same way as one built by hand. Anything
# that decides what ships — the version stamp, the package metadata, the
# architectures — lives here and not in a workflow.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# The version comes from the Git tag. No --always: on a commit with no tag
# reachable it emits a bare hash, and a digit-led hash is shaped exactly like a
# release version, so a snapshot could publish itself as one.
STAMP ?= $(shell git describe --tags --dirty 2>/dev/null)
VERSION = $(patsubst v%,%,$(STAMP))

MODULE := github.com/shellcell/snailmail
LDFLAGS := -s -w -X $(MODULE)/internal/version.stamped=$(STAMP)

DIST := dist
BUILD := build

# Platforms for the raw repository: the binaries a user downloads directly.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 freebsd/amd64
# Package architectures, written Go-style; nfpm translates each into the
# spelling its ecosystem uses.
PACKAGE_ARCHES := amd64 arm64

MAINTAINER ?= shellcell <noreply@shellcell.dev>

# nfpm builds deb, rpm and apk from one description, in pure Go. Pinned because
# it decides what goes inside a published package.
NFPM ?= go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.1

.PHONY: help
help: ## Show the available targets
	@grep -hE '^[a-z][a-zA-Z0-9_-]*:.*?## ' $(MAKEFILE_LIST) \
		| awk -F':.*?## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- checks

.PHONY: check
check: fmt vet test ## Everything CI checks, in the order that fails fastest

.PHONY: fmt
fmt: ## Fail if anything is unformatted
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "unformatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## Vet the default build and the one with S3 compiled out
	go vet ./...
	go vet -tags nos3 ./...

.PHONY: test
test: ## Run the suite
	go test -count=1 ./...

.PHONY: test-race
test-race: ## Run the suite under the race detector
	go test -race -count=1 ./...

.PHONY: test-nos3
test-nos3: ## Run the suite with S3 compiled out
	go test -tags nos3 -count=1 ./...

.PHONY: lint-workflows
lint-workflows: ## Lint the GitHub workflows, including their shell
	go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

# ---------------------------------------------------------------- release

.PHONY: release
release: require-version binaries packages checksums ## Build every release artifact

.PHONY: require-version
require-version:
	@if [ -z "$(STAMP)" ]; then \
		echo "no Git tag is reachable; a release needs one" >&2; exit 1; fi
	@case "$(STAMP)" in \
		*-dirty|*-[0-9]*-g[0-9a-f]*) \
			echo "refusing to release from $(STAMP), which is not an exact clean tag" >&2; exit 1 ;; \
	esac
	@echo "building $(VERSION)"

.PHONY: build
build: ## Build the binary for this machine
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD)/snailmail ./cmd/snailmail

.PHONY: binaries
binaries: require-version ## Cross-compiled tarballs, named for the raw convention
	@mkdir -p $(DIST) $(BUILD)
	@for platform in $(PLATFORMS); do \
		goos=$${platform%/*}; goarch=$${platform#*/}; \
		echo "  $$goos/$$goarch"; \
		GOOS=$$goos GOARCH=$$goarch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(BUILD)/snailmail ./cmd/snailmail; \
		tar -czf "$(DIST)/snailmail_$(VERSION)_$${goos}_$${goarch}.tar.gz" -C $(BUILD) snailmail; \
	done

.PHONY: packages
packages: require-version ## Debian, RPM and Alpine packages
	@mkdir -p $(DIST) $(BUILD)/package
	@for arch in $(PACKAGE_ARCHES); do \
		GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(BUILD)/package/snailmail ./cmd/snailmail; \
		for packager in deb rpm apk; do \
			echo "  $$arch $$packager"; \
			ARCH=$$arch VERSION=$(VERSION) MAINTAINER="$(MAINTAINER)" \
				$(NFPM) package --config nfpm.yaml --packager $$packager --target $(DIST)/ >/dev/null; \
		done; \
	done

.PHONY: checksums
checksums: ## Digests for everything built, which is what an adopter pins
	@cd $(DIST) && sha256sum ./*.tar.gz ./*.deb ./*.rpm ./*.apk > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

.PHONY: clean
clean: ## Remove build and release output
	rm -rf $(BUILD) $(DIST)
