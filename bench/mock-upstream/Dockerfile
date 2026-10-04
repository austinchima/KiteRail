# Benchmark-only tool server. Not part of the shipped image.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mock-upstream .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /mock-upstream /mock-upstream
EXPOSE 8082
ENTRYPOINT ["/mock-upstream"]
