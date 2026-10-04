# syntax=docker/dockerfile:1
# Base images are pinned by digest for reproducible, auditable builds;
# Dependabot (.github/dependabot.yml) proposes digest bumps.

FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS builder

WORKDIR /build
COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-w -s -X main.version=${VERSION}" -o /elodea ./cmd/server

# Runtime: distroless static, non-root, no shell or package manager.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
LABEL org.opencontainers.image.title="Elodea" \
      org.opencontainers.image.description="Inline policy enforcement proxy for autonomous AI agents" \
      org.opencontainers.image.source="https://github.com/austinchima/KiteRail" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

WORKDIR /app
COPY --from=builder /elodea /usr/local/bin/elodea
COPY LICENSE /licenses/LICENSE
# Default policy bundle; mount your own at /app/policies (hot-reloaded).
COPY policies/ /app/policies/

ENV ELODEA_POLICY_DIR=/app/policies
USER nonroot:nonroot
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/elodea", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/elodea"]
