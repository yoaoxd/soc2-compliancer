package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soc2-compliancer/app/internal/config"
	"github.com/soc2-compliancer/app/internal/db"
	"github.com/soc2-compliancer/app/internal/registry"
	"github.com/soc2-compliancer/app/internal/server"
)

func main() {
	cfg := config.FromEnv()
	ctx := context.Background()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	if err := db.RunMigrations(ctx, pool); err != nil {
		log.Fatalf("migrations failed: %v", err)
	}
	if err := registry.Seed(ctx, pool); err != nil {
		log.Fatalf("control registry seed failed: %v", err)
	}

	srv, err := server.New(cfg, pool)
	if err != nil {
		log.Fatalf("build server: %v", err)
	}

	httpServer := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: srv.Handler(),
	}

	schedulerCtx, schedulerCancel := context.WithCancel(ctx)
	defer schedulerCancel()
	srv.StartScheduler(schedulerCtx)

	go func() {
		log.Printf("soc2-compliancer api listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
