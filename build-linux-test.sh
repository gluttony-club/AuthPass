#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
go test ./...
go vet ./...
CGO_ENABLED=0 go build -tags notray -o dist/basicauth-helper ./cmd/basicauth-helper
