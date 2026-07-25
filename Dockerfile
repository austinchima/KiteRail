# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o /kiterail ./cmd/server

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -S kiterail && adduser -S kiterail -G kiterail

COPY --from=builder /kiterail /usr/local/bin/kiterail

USER kiterail
EXPOSE 8080

ENTRYPOINT ["kiterail"]
