package main

import (
	"context"
	"go-ast-processor-cli/internal/app"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	slog.Info("application starting",
		"pid", os.Getpid(),
		"uid", os.Getuid(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	ctx, stop := signal.NotifyContext(ctx,
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	appErr := make(chan error, 1)
	go func() {
		appErr <- app.NewApp().Run(ctx)
	}()

	select {
	case err := <-appErr:
		if err != nil {
			if ctx.Err() != nil {
				slog.Info("application cancelled", "reason", ctx.Err())
				os.Exit(0)
			} else {
				slog.Error("app run error", "error", err)
				os.Exit(1)
			}
		} else {
			slog.Info("application completed successfully")
			os.Exit(0)
		}
	case <-ctx.Done():
		slog.Info("shutting down")
		os.Exit(0)
	}
}
