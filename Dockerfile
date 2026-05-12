FROM golang:1.25-alpine AS builder
ARG VERSION

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o gost-tls-exporter .


FROM alpine:3.23

RUN apk --no-cache add ca-certificates && \
    addgroup -S exporter && adduser -S exporter -G exporter

WORKDIR /app

COPY --from=builder /app/gost-tls-exporter .

USER exporter

ENTRYPOINT ["./gost-tls-exporter"]
