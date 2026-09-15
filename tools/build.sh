#!/usr/bin/env bash
# Build Homelab RMM without make. Same targets as the Makefile:
#
#   tools/build.sh web        npm ci + npm run build (web/dist, embedded by the server)
#   tools/build.sh server     rmm-server for windows/amd64, windows/arm64, linux/amd64, linux/arm64
#   tools/build.sh agents     rmm-agent for those plus linux/arm (GOARM=7)
#   tools/build.sh all        web, server, agents
#   tools/build.sh test       go vet, go test, UI type-check + build
#   tools/build.sh package    dist/homelab-rmm-<os>-<arch>.zip (+ .tar.gz on linux) and SHA256SUMS
#   tools/build.sh checksums  regenerate dist/SHA256SUMS
#   tools/build.sh clean
#
# Environment: VERSION (default: git describe), GO, NPM, DIST (default dist).
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
LDFLAGS="-s -w -X ${MODULE}/internal/server.Version=${VERSION} -X ${MODULE}/internal/agent.Version=${VERSION}"

SERVER_PLATFORMS="windows/amd64 windows/arm64 linux/amd64 linux/arm64"
AGENT_PLATFORMS="windows/amd64 windows/arm64 linux/amd64 linux/arm64 linux/arm"

log() { printf '  %s\n' "$*"; }
die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }

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
	for f in "$DIST"/homelab-rmm-*.zip "$DIST"/homelab-rmm-*.tar.gz "$DIST"/rmm-server-* "$DIST"/rmm-agent-*; do
		# an unmatched glob stays literal; skip it (and never hash SHA256SUMS itself)
		[ -f "$f" ] && files+=("$(basename "$f")")
	done
	[ ${#files[@]} -gt 0 ] || die "nothing to checksum in $DIST (run: tools/build.sh server agents package)"
	(cd "$DIST" && printf '%s\n' "${files[@]}" | sort | xargs $tool > SHA256SUMS)
	log "wrote $DIST/SHA256SUMS"
}

do_package() {
	local p os arch name stage srv ap a
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
		if [ "$os" = windows ]; then cp "$srv" "$stage/rmm-server.exe"; else cp "$srv" "$stage/rmm-server"; fi
		# every agent binary goes into every archive: one server serves all device types
		for ap in $AGENT_PLATFORMS; do
			a=$(binname rmm-agent "${ap%/*}" "${ap#*/}")
			[ -f "$a" ] || die "missing $a (run: tools/build.sh agents)"
			cp "$a" "$stage/agents/"
		done
		cp README.md "$stage/"
		[ -f CHANGELOG.md ] && cp CHANGELOG.md "$stage/"
		[ -d docs ] && cp -r docs "$stage/docs"
		[ -d deploy ] && cp -r deploy "$stage/deploy"
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
		server)    build_platforms rmm-server "$SERVER_PLATFORMS" ;;
		agents)    build_platforms rmm-agent "$AGENT_PLATFORMS" ;;
		all)       do_web; build_platforms rmm-server "$SERVER_PLATFORMS"; build_platforms rmm-agent "$AGENT_PLATFORMS" ;;
		test)      do_test ;;
		package)   do_package ;;
		checksums) do_checksums ;;
		clean)     do_clean ;;
		-h|--help|help) sed -n '2,13p' "$0" ;;
		*) die "unknown target '$target' (web|server|agents|all|test|package|checksums|clean)" ;;
	esac
done
