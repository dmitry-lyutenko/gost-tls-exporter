# --- Этап 1: Сборка ---
# Используем свежий образ Go
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Кэшируем зависимости
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Собираем максимально оптимизированный бинарник
# -ldflags="-s -w" убирает отладочную информацию, уменьшая размер на 20-30%
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o gost-exporter .

# --- Этап 2: Финальный образ ---
FROM alpine:3.23

# Устанавливаем сертификаты и создаем пользователя
RUN apk --no-cache add ca-certificates && \
    addgroup -S exporter && adduser -S exporter -G exporter

WORKDIR /app

# Копируем бинарник
COPY --from=builder /app/gost-exporter .

# Переключаемся на пользователя без прав root
USER exporter

EXPOSE 19100

# Передаем сигналы завершения (SIGTERM) напрямую бинарнику
ENTRYPOINT ["/app/gost-exporter"]
