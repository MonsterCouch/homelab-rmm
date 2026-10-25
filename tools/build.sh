#!/usr/bin/env bash
# Build Homelab RMM without make. Same targets as the Makefile:
#
#   tools/build.sh web        npm ci + npm run build (web/dist, embedded by the server)
#   tools/build.sh server     rmm-server for windows/amd64, windows/arm64, linux/amd64, linux/arm64
#   tools/build.sh agents     rmm-agent for those plus linux/arm (GOARM=7)
#   tools/build.sh signer     rmm-signer (out-of-band approval signer) for windows/amd64 and windows/arm64
#   tools/build.sh all        web, server, agents, signer
#   tools/build.sh test       go vet, go test, UI type-check + build
#   tools/build.sh package    dist/homelab-rmm-<os>-<arch>.zip (+ .tar.gz on linux) and SHA256SUMS
#                             (archives what `server`, `agents` and `signer` built; it does NOT build
#                             anything, and refuses a binary older than the sources or web/dist
#                             it was built from - ALLOW_STALE_BUILD=1 packages it anyway)
#   tools/build.sh checksums  regenerate dist/SHA256SUMS
#   tools/build.sh clean
#
# `server` and `package` refuse to run without a built UI in web/dist, because the
# server binary embeds it; ALLOW_EMPTY_WEB=1 overrides that for a --dev-web binary.
#
# The Windows archives also carry rmm-signer-windows-<arch>.exe beside rmm-server.exe.
#
# Environment: VERSION (default: git describe), GO, NPM, DIST (default dist),
# ALLOW_EMPTY_WEB, ALLOW_STALE_BUILD.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

GO=${GO:-go}
NPM=${NPM:-npm}
DIST=${DIST:-dist}
# absolute so a `cd` into a stage directory never changes where archives land
case "$DIST" in /*) ;; *) DIST="$ROOT/$DIST" ;; esac
VERSION=${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}
MODULE=github.com/MonsterCouch/homelab-rmm
LDFLAGS="-s -w -X ${MODULE}/internal/server.Version=${VERSION} -X ${MODULE}/internal/agent.Version=${VERSION} -X main.Version=${VERSION}"

SERVER_PLATFORMS="windows/amd64 windows/arm64 linux/amd64 linux/arm64"
AGENT_PLATFORMS="windows/amd64 windows/arm64 linux/amd64 linux/arm64 linux/arm"
# rmm-signer signs with the Windows WebAuthn API, so only Windows gets a binary.
SIGNER_PLATFORMS="windows/amd64 windows/arm64"

log() { printf '  %s\n' "$*"; }
die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }

# rmm-server embeds web/dist (web/embed.go, `go:embed all:dist`). That directory
# is gitignored apart from .gitkeep, so on a fresh clone the embed succeeds with
# ONE EMPTY FILE and the Go build says nothing at all - the archive then ships a
# server whose console is a directory listing of .gitkeep. Nothing downstream
# can notice, so the check lives here, before a single server binary is built.
# ALLOW_EMPTY_WEB=1 is the deliberate escape hatch (a binary that will run with
# --dev-web, or a UI-less smoke build).
require_web() {
	if [ -n "${ALLOW_EMPTY_WEB:-}" ]; then
		log "ALLOW_EMPTY_WEB is set: building rmm-server without a built UI"
		return 0
	fi
	[ -f web/dist/index.html ] || die "web/dist/index.html is missing: run 'tools/build.sh web' (or 'make web') first. rmm-server embeds web/dist, so this build would ship a server with no console. Set ALLOW_EMPTY_WEB=1 to build one on purpose."
}

# binname rmm-agent linux amd64 -> dist/rmm-agent-linux-amd64 (.exe on windows)
binname() {
	local n="$DIST/$1-$2-$3"
	[ "$2" = windows ] && n="$n.exe"
	printf '%s' "$n"
}

build_one() { # command os arch
	local cmd=$1 os=$2 arch=$3 out
	out=$(binname "$cmd" "$os" "$arch")
	local -a env=(CGO_ENABLED=0 GOOS="$os" GOARCH="$arch")
	# GOARM is only meaningful for 32-bit arm; v7 covers every Pi 2+ and most SBCs.
	[ "$arch" = arm ] && env+=(GOARM=7)
	log "build $out ($VERSION)"
	mkdir -p "$DIST"
	env "${env[@]}" "$GO" build -trimpath -ldflags "$LDFLAGS" -o "$out" "./cmd/$cmd"
}

build_platforms() { # command "os/arch os/arch ..."
	local p
	for p in $2; do
		build_one "$1" "${p%/*}" "${p#*/}"
	done
}

do_web() {
	(cd web && "$NPM" ci && "$NPM" run build)
}

do_test() {
	"$GO" vet ./...
	"$GO" test ./...
	(cd web && "$NPM" run build)
}

# zip_dir <stage dir> <zip path>: prefer zip(1) because it stores unix modes;
# fall back to python's zipfile so the build works on a minimal container.
zip_dir() {
	local stage=$1 zip=$2
	rm -f "$zip"
	if command -v zip >/dev/null 2>&1; then
		(cd "$stage" && zip -qr -X "$zip" .)
	elif command -v python3 >/dev/null 2>&1; then
		(cd "$stage" && python3 - "$zip" <<'PY'
import os, sys, zipfile
out = sys.argv[1]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk("."):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, "."))
PY
		)
	else
		die "neither zip nor python3 is available to create $zip"
	fi
}

sha256_tool() {
	if command -v sha256sum >/dev/null 2>&1; then echo sha256sum
	elif command -v shasum >/dev/null 2>&1; then echo "shasum -a 256"
	else die "no sha256sum or shasum found"; fi
}

do_checksums() {
	local tool f
	local -a files=()
	tool=$(sha256_tool)
	[ -d "$DIST" ] || die "no $DIST directory to checksum"
	for f in "$DIST"/homelab-rmm-*.zip "$DIST"/homelab-rmm-*.tar.gz "$DIST"/rmm-server-* "$DIST"/rmm-agent-* "$DIST"/rmm-signer-*; do
		# an unmatched glob stays literal; skip it (and never hash SHA256SUMS itself)
		[ -f "$f" ] && files+=("$(basename "$f")")
	done
	[ ${#files[@]} -gt 0 ] || die "nothing to checksum in $DIST (run: tools/build.sh server agents package)"
	(cd "$DIST" && printf '%s\n' "${files[@]}" | sort | xargs $tool > SHA256SUMS)
	log "wrote $DIST/SHA256SUMS"
}

# first_newer <binary>: prints one source file that is newer than the binary,
# or nothing. `package` archives what `server` and `agents` left in dist/, so a
# run that skips those ships whatever was built last time - a server binary
# that predates the feature, beside the docs that describe it. Nothing about
# that archive looks wrong until someone runs it, so it is refused here.
# -print -quit rather than `| head -1`: closing the pipe on a running find is a
# SIGPIPE, which under `set -o pipefail` kills the build with 141 and no message.
first_newer() {
	local ref=$1 hit=''
	hit=$(find . -path ./dist -prune -o -path ./web/node_modules -prune -o -path ./node_modules -prune -o \
		-type f -newer "$ref" \( -name '*.go' -o -name go.mod -o -name go.sum \) -print -quit 2>/dev/null) || true
	if [ -z "$hit" ] && [ -d web/dist ]; then
		hit=$(find web/dist -type f -newer "$ref" -print -quit 2>/dev/null) || true
	fi
	printf '%s' "$hit"
}

# fresh <binary> <rebuild hint>: die if anything it is built from is newer.
fresh() {
	local newer
	[ -n "${ALLOW_STALE_BUILD:-}" ] && return 0
	newer=$(first_newer "$1")
	[ -n "$newer" ] || return 0
	die "$1 is older than $newer: it would ship a binary built from different source than this tree. Run 'tools/build.sh $2' (or 'tools/build.sh all') first, or set ALLOW_STALE_BUILD=1 to package it anyway."
}

do_package() {
	local p os arch name stage srv ap a sp s
	require_web
	mkdir -p "$DIST"
	rm -f "$DIST"/homelab-rmm-*.zip "$DIST"/homelab-rmm-*.tar.gz
	for p in $SERVER_PLATFORMS; do
		os=${p%/*}; arch=${p#*/}
		name="homelab-rmm-$os-$arch"
		stage="$DIST/pkg/$name"
		rm -rf "$stage"
		mkdir -p "$stage/agents"
		srv=$(binname rmm-server "$os" "$arch")
		[ -f "$srv" ] || die "missing $srv (run: tools/build.sh server)"
		fresh "$srv" server
		if [ "$os" = windows ]; then cp "$srv" "$stage/rmm-server.exe"; else cp "$srv" "$stage/rmm-server"; fi
		# every agent binary goes into every archive: one server serves all device types
		for ap in $AGENT_PLATFORMS; do
			a=$(binname rmm-agent "${ap%/*}" "${ap#*/}")
			[ -f "$a" ] || die "missing $a (run: tools/build.sh agents)"
			fresh "$a" agents
			cp "$a" "$stage/agents/"
		done
		# the signer ships in the Windows archives only, where it can run
		if [ "$os" = windows ]; then
			for sp in $SIGNER_PLATFORMS; do
				s=$(binname rmm-signer "${sp%/*}" "${sp#*/}")
				[ -f "$s" ] || die "missing $s (run: tools/build.sh signer)"
				fresh "$s" signer
				cp "$s" "$stage/"
			done
		fi
		cp README.md "$stage/"
		[ -f CHANGELOG.md ] && cp CHANGELOG.md "$stage/"
		[ -d docs ] && cp -r docs "$stage/docs"
		[ -d deploy ] && cp -r deploy "$stage/deploy"
		# The attributions the compiled-in components require have to be in
		# the archive, not just in the repository: this archive is a copy of
		# the software and carries their code inside the binaries.
		if [ -f THIRD-PARTY-NOTICES.md ]; then
			cp THIRD-PARTY-NOTICES.md "$stage/THIRD-PARTY-NOTICES.md"
		else
			die "THIRD-PARTY-NOTICES.md is missing; the archive must carry the third-party attributions"
		fi
		if [ -f LICENSE ]; then
			cp LICENSE "$stage/LICENSE"
		else
			# placeholder until the repository carries a licence file
			printf 'Homelab RMM %s\n\nNo LICENSE file is present in this build. See the project repository for licensing terms.\n' "$VERSION" > "$stage/LICENSE"
		fi
		printf '%s\n' "$VERSION" > "$stage/VERSION"
		zip_dir "$stage" "$DIST/$name.zip"
		log "packaged $DIST/$name.zip"
		if [ "$os" = linux ]; then
			# tar keeps the executable bit whatever unzips it on the other side
			tar -C "$stage" -czf "$DIST/$name.tar.gz" .
			log "packaged $DIST/$name.tar.gz"
		fi
	done
	rm -rf "$DIST/pkg"
	do_checksums
}

do_clean() {
	rm -rf "$DIST"
	find web/dist -mindepth 1 ! -name .gitkeep -delete 2>/dev/null || true
}

[ $# -gt 0 ] || set -- all
for target in "$@"; do
	case "$target" in
		web)       do_web ;;
		server)    require_web; build_platforms rmm-server "$SERVER_PLATFORMS" ;;
		agents)    build_platforms rmm-agent "$AGENT_PLATFORMS" ;;
		signer)    build_platforms rmm-signer "$SIGNER_PLATFORMS" ;;
		all)       do_web; require_web; build_platforms rmm-server "$SERVER_PLATFORMS"; build_platforms rmm-agent "$AGENT_PLATFORMS"; build_platforms rmm-signer "$SIGNER_PLATFORMS" ;;
		test)      do_test ;;
		package)   do_package ;;
		checksums) do_checksums ;;
		clean)     do_clean ;;
		-h|--help|help) sed -n '2,23p' "$0" ;;
		*) die "unknown target '$target' (web|server|agents|signer|all|test|package|checksums|clean)" ;;
	esac
done
