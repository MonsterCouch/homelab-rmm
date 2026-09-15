# syntax=docker/dockerfile:1
#
# Homelab RMM server image. Three stages:
#   web    builds the React UI (web/dist), which the Go binary embeds
#   build  cross-compiles the server for the target platform and every agent
#   final  distroless static image: /rmm-server plus /agents/rmm-agent-<os>-<arch>
#
# Agent lookup: the server searches <data>/agents/ first, then the directory
# beside its own executable (internal/server/install.go). With the binary at
# /rmm-server and the agents at /agents the second rule matches, so the
# image needs no extra mount; drop newer agent builds into /data/agents to
# override them without rebuilding the image.
#
#   docker build -t homelab-rmm .
#   docker buildx build --platform linux/amd64,linux/arm64 -t homelab-rmm .

ARG NODE_VERSION=22
ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
RUN apk add --no-cache git bash
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
ENV MODULE=github.com/MonsterCouch/homelab-rmm
# every agent binary (all five platforms) so one image can enrol any device
RUN VERSION="$VERSION" bash tools/build.sh agents
RUN mkdir -p /out /data \
 && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath \
      -ldflags "-s -w -X ${MODULE}/internal/server.Version=${VERSION} -X ${MODULE}/internal/agent.Version=${VERSION}" \
      -o /out/rmm-server ./cmd/rmm-server

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="Homelab RMM" \
      org.opencontainers.image.source="https://github.com/MonsterCouch/homelab-rmm"
COPY --from=build /out/rmm-server /rmm-server
COPY --from=build /src/dist/rmm-agent-* /agents/
# an empty /data owned by the nonroot user, so a named volume inherits the ownership
COPY --from=build --chown=65532:65532 /data /data
ENV RMM_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8443
USER nonroot
ENTRYPOINT ["/rmm-server"]
CMD ["run", "--data", "/data", "--listen", ":8443"]
