package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/maxyotka/gost-crypto"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Версия приложения
var version = "unknown"

type cacheEntry struct {
	metrics   *prometheus.Registry
	lastCheck time.Time
}

func main() {
	listenPort := flag.Int("port", 9100, "Port to listen on")
	listenAddress := flag.String("address", "0.0.0.0", "Address to listen on")
	cacheTTL := flag.Duration("cache-ttl", 60*time.Minute, "Cache TTL (default 60m)")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	logFormat := flag.String("log-format", "text", "Log format: text, json")
	flag.Parse()

	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(handler))

	metricsCache := &sync.Map{}

	http.HandleFunc("/probe", returnProbeHandler(metricsCache, cacheTTL))
	http.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", *listenAddress, *listenPort),
		Handler: nil, // используем DefaultServeMux
	}

	srvc := make(chan struct{})
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	slog.Info("exporter started", "version", version, "address", *listenAddress, "port", *listenPort, "cache_ttl", cacheTTL.String())
	go func() {

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("failed to start HTTP server", "err", err)
			close(srvc)
		}
	}()

	for {
		select {
		case <-term:
			slog.Info("shutting down gracefully")
			// Создаем контекст с таймаутом, чтобы не ждать вечно
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			// Shutdown плавно закрывает все соединения и останавливает сервер
			if err := srv.Shutdown(ctx); err != nil {
				slog.Error("server forced to shutdown", "err", err)
				cancel()
				os.Exit(1)
			}

			slog.Info("server stopped")
			cancel()
			os.Exit(0)
		case <-srvc:
			os.Exit(1)
		}
	}

}

func returnProbeHandler(cache *sync.Map, cacheTTL *time.Duration) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawTarget := r.URL.Query().Get("target")
		if rawTarget == "" {
			http.Error(w, "Target is required", http.StatusBadRequest)
			return
		}

		if val, ok := cache.Load(rawTarget); ok {
			entry := val.(cacheEntry)

			if time.Since(entry.lastCheck) < *cacheTTL {
				slog.Info("returning cached data", "target", rawTarget, "age", time.Since(entry.lastCheck).Round(time.Second))

				promhttp.HandlerFor(entry.metrics, promhttp.HandlerOpts{}).ServeHTTP(w, r)
				return
			}
		}

		host, port, err := prepareTarget(rawTarget)
		if err != nil {
			slog.Warn("invalid target format", "target", rawTarget, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cert, err := Connect(ctx, host, port)
		if err != nil {
			if ctx.Err() != nil {
				slog.Debug("probe cancelled", "target", rawTarget, "err", ctx.Err())
			} else {
				slog.Error("probe failed", "target", rawTarget, "err", err)
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		registry := metrics(cert)
		newCacheEntry := cacheEntry{
			metrics:   registry,
			lastCheck: time.Now(),
		}
		cache.Store(rawTarget, newCacheEntry)

		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}

}

func prepareTarget(rawTarget string) (string, string, error) {
	if strings.HasPrefix(rawTarget, "http://") {
		return "", "", fmt.Errorf("HTTP protocol is not supported, use HTTPS or host:port")
	}

	target := strings.TrimPrefix(rawTarget, "https://")

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// Если ошибка — значит порта нет (случай example.org)
		host = target
		port = "443"
	}
	return host, port, nil
}
