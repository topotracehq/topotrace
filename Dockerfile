# Multi-stage build: compile with the full Go toolchain, ship only the
# static binary in a minimal runtime image.

FROM golang:1.24-alpine AS build
WORKDIR /src

# Dependencies (currently just github.com/lib/pq, for pgstore) are
# vendored into vendor/ and committed to the repo -- see the README --
# so the build below never touches the network, no `go mod download`
# step needed or wanted.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/muster ./cmd/muster
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/demoagent ./cmd/demoagent

# --- runtime image ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    addgroup -S muster && adduser -S muster -G muster

WORKDIR /app
COPY --from=build /out/muster /out/demoagent ./
COPY testdata ./testdata

RUN mkdir -p /app/data && chown -R muster:muster /app
USER muster

EXPOSE 8080 9090
VOLUME ["/app/data"]

ENTRYPOINT ["/app/muster"]
CMD ["-data-dir", "/app/data"]
