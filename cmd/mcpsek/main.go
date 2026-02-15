package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/mcpsek/mcpsek/internal/api"
	"github.com/mcpsek/mcpsek/internal/config"
	"github.com/mcpsek/mcpsek/internal/database"
	"github.com/mcpsek/mcpsek/internal/scanner"
	"github.com/mcpsek/mcpsek/internal/scheduler"
	"github.com/mcpsek/mcpsek/internal/web"
)

func main() {
	log.Println("mcpsek starting...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create clone directory if it doesn't exist
	if err := os.MkdirAll(cfg.CloneDir, 0755); err != nil {
		log.Fatalf("Failed to create clone directory: %v", err)
	}

	// Connect to database
	ctx := context.Background()
	db, err := database.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("Database connected")

	// Check database health
	if err := db.Health(ctx); err != nil {
		log.Fatalf("Database health check failed: %v", err)
	}

	// Initialize scanner
	scn := scanner.New(cfg.CloneDir, db)

	// Initialize scheduler
	sched := scheduler.New(
		db,
		scn,
		cfg.GitHubToken,
		cfg.ScanWorkers,
		cfg.ScanInterval,
		cfg.DiscoveryInterval,
	)

	// Start scheduler in background
	schedCtx, schedCancel := context.WithCancel(context.Background())
	defer schedCancel()

	go func() {
		if err := sched.Start(schedCtx); err != nil {
			log.Printf("Scheduler error: %v", err)
		}
	}()

	// Initialize API
	apiHandler := api.New(db)

	// Initialize web UI
	webHandler, err := web.New(db, "internal/web/templates")
	if err != nil {
		log.Fatalf("Failed to initialize web handler: %v", err)
	}

	// Setup router
	r := chi.NewRouter()

	// Mount API routes
	r.Mount("/api/v1", apiHandler.Router())

	// Mount web routes
	r.Mount("/", webHandler.Router())

	// Serve static files
	fileServer := http.FileServer(http.Dir("static"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: r,
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutdown signal received, stopping...")
		schedCancel()
		server.Shutdown(context.Background())
	}()

	// Start server
	log.Printf("mcpsek listening on %s", cfg.HTTPAddr)
	log.Printf("Scanner: %d workers, scan interval: %s", cfg.ScanWorkers, cfg.ScanInterval)
	log.Printf("Discovery interval: %s", cfg.DiscoveryInterval)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("mcpsek stopped")
}
