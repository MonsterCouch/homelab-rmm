# Homelab RMM build.
#
#   make all       web UI + every server and agent binary into dist/
#   make web       npm ci && npm run build in web/ (the server embeds web/dist)
#   make server    rmm-server for windows/amd64, windows/arm64, linux/amd64, linux/arm64
#   make agents    rmm-agent for those four plus linux/arm (GOARM=7)
#   make test      go vet, go test, and a TypeScript/Vite build of the UI
#   make package   dist/homelab-rmm-<os>-<arch>.zip per server platform (+ .tar.gz on
#                  linux), each with the server, every agent binary, docs and SHA256SUMS.
#                  It archives what `server` and `agents` built and does NOT build the UI:
#                  `make all` (or `make web` first) is what puts a console in the archive.
#   make clean     remove dist/ and the built UI
#
# Building rmm-server without a built web/dist is refused (the binary embeds it);
# `make ALLOW_EMPTY_WEB=1 server` builds one anyway, for use with --dev-web.
#
# Override on the command line: make VERSION=v1.2.3 GO=/usr/local/go/bin/go
# tools/build.sh does the same without make; tools/build.ps1 is the Windows twin.

SHELL   := /bin/bash
GO      ?= go
NPM     ?= npm
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
MODULE  := github.com/MonsterCouch/homelab-rmm
DIST    ?= dist

# -s -w strips symbols and DWARF; the two -X flags stamp the version each
# binary prints and reports (server.Version, agent.Version).
LDFLAGS := -s -w -X $(MODULE)/internal/server.Version=$(VERSION) -X $(MODULE)/internal/agent.Version=$(VERSION)

SERVER_PLATFORMS := windows/amd64 windows/arm64 linux/amd64 linux/arm64
AGENT_PLATFORMS  := windows/amd64 windows/arm64 linux/amd64 linux/arm64 linux/arm

# rmm-server embeds web/dist (web/embed.go, `go:embed all:dist`), and web/dist is
# gitignored apart from .gitkeep: on a fresh clone the embed quietly succeeds with
# one empty file, the Go build reports nothing, and `make package` archives a
# server whose console is a directory listing. So every rmm-server build checks
# for a built UI first. ALLOW_EMPTY_WEB=1 is the deliberate override.
WEB_GUARD = @test -n "$(ALLOW_EMPTY_WEB)" || test -f web/dist/index.html || { \
	echo "make: web/dist/index.html is missing - run 'make web' (or 'make all') first." >&2; \
	echo "      rmm-server embeds web/dist, so this build would ship a server with no console." >&2; \
	echo "      'make ALLOW_EMPTY_WEB=1 ...' builds one on purpose (for use with --dev-web)." >&2; \
	exit 1; }

export VERSION GO NPM DIST

.PHONY: all web server agents test package checksums clean help fmt vet FORCE

all: web
	$(MAKE) server agents

web:
	cd web && $(NPM) ci && $(NPM) run build

# ---- cross-compilation -------------------------------------------------------
# One rule per platform, generated below. Binaries are named the way the
# server looks them up (rmm-agent-<os>-<arch>[.exe], see internal/server/install.go).

# $(1) command, $(2) GOOS, $(3) GOARCH, $(4) extra environment (GOARM=7 for arm)
define build_rule
$(DIST)/$(1)-$(2)-$(3)$(if $(filter windows,$(2)),.exe,): FORCE
	@mkdir -p $(DIST)
	$(if $(filter rmm-server,$(1)),$(WEB_GUARD),)
	@echo "  build $$@ ($(VERSION))"
	@CGO_ENABLED=0 GOOS=$(2) GOARCH=$(3) $(4) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$@ ./cmd/$(1)
endef

os_of   = $(word 1,$(subst /, ,$(1)))
arch_of = $(word 2,$(subst /, ,$(1)))
binary  = $(DIST)/$(1)-$(subst /,-,$(2))$(if $(filter windows,$(call os_of,$(2))),.exe,)

$(foreach p,$(SERVER_PLATFORMS),$(eval $(call build_rule,rmm-server,$(call os_of,$(p)),$(call arch_of,$(p)),)))
$(foreach p,$(AGENT_PLATFORMS),$(eval $(call build_rule,rmm-agent,$(call os_of,$(p)),$(call arch_of,$(p)),$(if $(filter arm,$(call arch_of,$(p))),GOARM=7,))))

SERVER_BINS := $(foreach p,$(SERVER_PLATFORMS),$(call binary,rmm-server,$(p)))
AGENT_BINS  := $(foreach p,$(AGENT_PLATFORMS),$(call binary,rmm-agent,$(p)))

server: $(SERVER_BINS)
agents: $(AGENT_BINS)

FORCE:

# ---- quality -----------------------------------------------------------------

test:
	$(GO) vet ./...
	$(GO) test ./...
	cd web && $(NPM) run build

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

# ---- packaging ---------------------------------------------------------------
# The archive layout is what the quick start expects: rmm-server(.exe) at the
# root, agents/ beside it (the server serves them from there), README, docs.

package: server agents
	tools/build.sh package

checksums:
	tools/build.sh checksums

clean:
	rm -rf $(DIST)
	find web/dist -mindepth 1 ! -name .gitkeep -delete 2>/dev/null || true

help:
	@sed -n '2,17p' $(MAKEFILE_LIST)
