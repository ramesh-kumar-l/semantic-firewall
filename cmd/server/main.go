package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/ramesh152/semantic-firewall/config"
	"github.com/ramesh152/semantic-firewall/internal/audit"
	"github.com/ramesh152/semantic-firewall/internal/detection"
	inspectmw "github.com/ramesh152/semantic-firewall/internal/middleware"
	"github.com/ramesh152/semantic-firewall/internal/policy"
	"github.com/ramesh152/semantic-firewall/internal/scoring"
	"github.com/ramesh152/semantic-firewall/internal/telemetry"
	"github.com/ramesh152/semantic-firewall/pkg/types"
)

const (
	version      = "0.1.0"
	drainTimeout = 10 * time.Second
)

func main() {
	configPath := flag.String("config", "", "Path to config file (optional)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("config.load.error", "error", err.Error())
		os.Exit(1)
	}

	tel, err := telemetry.New(cfg.Telemetry.ServiceName, cfg.Telemetry.ServiceVersion)
	if err != nil {
		slog.Error("telemetry.init.error", "error", err.Error())
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tel.Shutdown(shutdownCtx); err != nil {
			slog.Error("telemetry.shutdown.error", "error", err.Error())
		}
	}()

	instruments, err := telemetry.NewInstruments(tel.Meter)
	if err != nil {
		slog.Error("metrics.init.error", "error", err.Error())
		os.Exit(1)
	}

	auditLogger, err := audit.NewJSONLLogger(cfg.Audit.Path)
	if err != nil {
		slog.Error("audit.init.error", "error", err.Error())
		os.Exit(1)
	}
	defer auditLogger.Close()

	scorer := scoring.NewRuleBasedScorer()
	detector := detection.NewInjectionDetector()
	policyEngine := policy.NewRuleEngine(
		cfg.Policy.DenyThreshold,
		types.Decision(cfg.Policy.DefaultAction),
	)

	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(chimw.RequestID)

	r.Get("/health", healthHandler(version))
	r.Post("/v1/inspect", inspectmw.Handler(
		scorer,
		detector,
		policyEngine,
		auditLogger,
		tel,
		instruments,
		time.Duration(cfg.Server.InspectTimeoutMs)*time.Millisecond,
		cfg.Server.MaxPromptBytes,
	))

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeoutMs) * time.Millisecond,
	}

	slog.Info("server.starting",
		"addr", addr,
		"version", version,
	)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.ListenAndServe()
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("server.error", "error", err.Error())
			os.Exit(1)
		}
	case sig := <-quit:
		slog.Info("server.shutdown.signal", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("server.shutdown.error", "error", err.Error())
		}
	}

	slog.Info("server.stopped")
}

func healthHandler(ver string) http.HandlerFunc {
	start := time.Now()
	return func(w http.ResponseWriter, r *http.Request) {
		uptime := int64(time.Since(start).Seconds())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q,"uptime_seconds":%d}`, ver, uptime)
	}
}
