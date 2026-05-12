package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/maxyotka/gost-crypto"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	listenPort    = 19100
	listenAddress = "0.0.0.0"
	cacheTTL      = 10 * time.Minute // Настрой по вкусу
)

func main() {
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

	// ########################################################################
	http.HandleFunc("/probe", probeHandler)
	http.Handle("/metrics", promhttp.Handler())

	srvc := make(chan struct{})
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	slog.Info("exporter started", "address", listenAddress, "port", listenPort)
	go func() {

		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", listenAddress, listenPort), nil); err != nil {
			slog.Error("failed to start HTTP server", "err", err)
			close(srvc)
		}
	}()

	for {
		select {
		case <-term:
			slog.Info("shutting down gracefully")
			os.Exit(0)
		case <-srvc:
			os.Exit(1)
		}
	}

	// ########################################################################

}

type cacheEntry struct {
	metrics   *prometheus.Registry
	lastCheck time.Time
}

func getFromCache(target string) (*cacheEntry, bool) {
	val, ok := certCache.Load(target)
	if !ok {
		return nil, false
	}
	entry := val.(cacheEntry)
	return &entry, true
}

var (
	certCache sync.Map
)

func probeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "Target is required", http.StatusBadRequest)
		return
	}

	if val, ok := certCache.Load(target); ok {
		entry := val.(cacheEntry)
		if time.Since(entry.lastCheck) < cacheTTL {
			slog.Info("returning cached data", "target", target, "age", time.Since(entry.lastCheck).Round(time.Second))

			promhttp.HandlerFor(entry.metrics, promhttp.HandlerOpts{}).ServeHTTP(w, r)
			return
		}
	}

	cert, err := Connect(ctx, target, "443")
	if err != nil {
		if ctx.Err() != nil {
			slog.Debug("probe cancelled", "err", ctx.Err())
		} else {
			slog.Error("probe failed", "target", target, "err", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	registry := metrics(cert)
	newCacheEntry := cacheEntry{
		metrics:   registry,
		lastCheck: time.Now(),
	}
	certCache.Store(target, newCacheEntry)

	// // Отдаем метрики
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}
