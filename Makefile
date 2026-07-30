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

# Built without cgo, so every binary is statically linked and runs against any
# libc. Left to Go's default this varies by the machine that built it: cgo is on
# for a native build when a C compiler is present and off when cross-compiling.
# On an amd64 runner that made the amd64 binaries link glibc while the
# cross-compiled arm64 ones stayed static — so snailmail_0.1.3-r1_x86_64.apk
# installed on Alpine and then failed with "failed to open elf at
# /lib64/ld-linux-x86-64.so.2", while the aarch64 package worked. Exported, so
# it covers every go build here rather than the ones remembered.
export CGO_ENABLED := 0

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
# verify-packages is part of building a release, not a step a workflow remembers
# to add. v0.1.3 shipped an apk that could not run because the only check that
# ran the binary ran it on the build machine, which is not where it fails.
release: require-version binaries packages verify-packages checksums ## Build and verify every release artifact

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

# Distributions the packages are installed into for verification. Installing is
# not evidence that a package works: the broken apk installed cleanly and
# reported the right version to "apk info -v", and only running the binary showed
# that it could not start.
DEB_IMAGE ?= debian:bookworm-slim
RPM_IMAGE ?= fedora:41
APK_IMAGE ?= alpine:3.21

.PHONY: verify-packages
verify-packages: ## Install every built package in its distribution and run it
	@command -v docker >/dev/null || { echo "docker is needed to install the packages" >&2; exit 1; }
	@run_package() { \
	    arch=$$1; image=$$2; package=$$3; install=$$4; \
	    echo "  $$arch $$image $$(basename "$$package")"; \
	    test -f "$$package" || { echo "missing $$package" >&2; exit 1; }; \
	    target=/tmp/$$(basename "$$package"); \
	    reported=$$(docker run --rm --platform "linux/$$arch" \
	        -v "$$PWD/$$package:$$target:ro" "$$image" \
	        sh -c "$$install $$target >/dev/null 2>&1 && snailmail version --json" 2>&1) || { \
	        echo "$$reported" >&2; \
	        echo "snailmail does not run after installing $$package on $$image" >&2; \
	        exit 1; }; \
	    case "$$reported" in *'"$(VERSION)"'*) return 0 ;; esac; \
	    echo "installed $$package reports $$reported, want $(VERSION)" >&2; \
	    exit 1; \
	}; \
	for arch in $(PACKAGE_ARCHES); do \
	    case $$arch in \
	        amd64) rpmarch=x86_64; apkarch=x86_64 ;; \
	        arm64) rpmarch=aarch64; apkarch=aarch64 ;; \
	        *) echo "no distribution images known for $$arch" >&2; exit 1 ;; \
	    esac; \
	    run_package "$$arch" "$(DEB_IMAGE)" "$(DIST)/snailmail_$(VERSION)-1_$${arch}.deb" "dpkg -i"; \
	    run_package "$$arch" "$(RPM_IMAGE)" "$(DIST)/snailmail-$(VERSION)-1.$${rpmarch}.rpm" "rpm -i --nodeps"; \
	    run_package "$$arch" "$(APK_IMAGE)" "$(DIST)/snailmail_$(VERSION)-r1_$${apkarch}.apk" "apk add --allow-untrusted --quiet"; \
	done
	@echo "every package installs and runs"

.PHONY: checksums
checksums: ## Digests for everything built, which is what an adopter pins
	@cd $(DIST) && sha256sum ./*.tar.gz ./*.deb ./*.rpm ./*.apk > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

.PHONY: clean
clean: ## Remove build and release output
	rm -rf $(BUILD) $(DIST)
