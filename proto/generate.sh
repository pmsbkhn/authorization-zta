#!/usr/bin/env bash
# Regenerate the Go gRPC stubs from the .proto files.
#
# Requires:
#   brew install protobuf
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#
# The generated *.pb.go files are committed; run this only when a .proto changes.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$(go env GOPATH)/bin:$PATH"

protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/authzen/v1/authzen.proto

echo "generated: proto/authzen/v1/*.pb.go"
