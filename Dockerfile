# Stage 1: Build
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Download dependencies first (layer cache)
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /llm-hasher \
    ./cmd/llm-hasher

# Stage 2: Runtime (minimal)
FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /llm-hasher /app/llm-hasher

EXPOSE 8080
ENTRYPOINT ["/app/llm-hasher"]
