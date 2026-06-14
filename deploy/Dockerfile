# Build all VSP service binaries once, ship them in a minimal distroless image.
# Static (CGO disabled) so they run in distroless/static with no libc.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/pdp       ./cmd/pdp       && \
    CGO_ENABLED=0 go build -trimpath -o /out/gateway   ./cmd/gateway   && \
    CGO_ENABLED=0 go build -trimpath -o /out/multibill ./cmd/multibill && \
    CGO_ENABLED=0 go build -trimpath -o /out/wallet    ./cmd/wallet    && \
    CGO_ENABLED=0 go build -trimpath -o /out/caepemit  ./cmd/caepemit

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/ /app/
