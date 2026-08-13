// Command lfp-connect-auth runs the Authentik control plane and NATS Auth Callout.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/regbo/lfp-pipe/controlplane/internal/config"
	"github.com/regbo/lfp-pipe/controlplane/internal/httpapi"
	"github.com/regbo/lfp-pipe/controlplane/internal/natsauth"
	"github.com/regbo/lfp-pipe/controlplane/internal/ticket"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	tickets := ticket.NewSigner(cfg.TicketSecret, cfg.TicketTTL)
	calloutService, err := natsauth.Start(ctx, cfg, tickets, logger)
	if err != nil {
		logger.Error("NATS Auth Callout startup failed", "error", err)
		os.Exit(1)
	}
	defer func() { _ = calloutService.Close() }()

	api, err := httpapi.New(ctx, cfg, tickets, calloutService.NATS(), logger)
	if err != nil {
		logger.Error("HTTP API startup failed", "error", err)
		os.Exit(1)
	}
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Managed-client configuration events are intentionally long-lived.
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	logger.Info("LFP Connect auth service listening", "address", cfg.HTTPAddr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server failed", "error", err)
		os.Exit(1)
	}
}
