package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Database
	DatabaseURL string

	// HTTP Server
	HTTPAddr string

	// Scanner
	CloneDir      string
	ScanWorkers   int
	ScanInterval  time.Duration

	// Discovery
	DiscoveryInterval time.Duration
	GitHubToken       string

	// API
	APIRateLimit int // requests per minute

	// Shodan (optional)
	ShodanAPIKey string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:       getEnv("MCPSEK_DB_URL", "postgres://localhost:5432/mcpsek?sslmode=disable"),
		HTTPAddr:          getEnv("MCPSEK_HTTP_ADDR", ":8080"),
		CloneDir:          getEnv("MCPSEK_CLONE_DIR", "/tmp/mcpsek-repos"),
		ScanWorkers:       getEnvInt("MCPSEK_SCAN_WORKERS", 4),
		ScanInterval:      getEnvDuration("MCPSEK_SCAN_INTERVAL", "24h"),
		DiscoveryInterval: getEnvDuration("MCPSEK_DISCOVERY_INTERVAL", "168h"), // 7 days
		GitHubToken:       getEnv("MCPSEK_GITHUB_TOKEN", ""),
		APIRateLimit:      getEnvInt("MCPSEK_API_RATE_LIMIT", 100),
		ShodanAPIKey:      getEnv("MCPSEK_SHODAN_API_KEY", ""),
	}

	// Validate required fields
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("MCPSEK_DB_URL is required")
	}

	return cfg, nil
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt retrieves an environment variable as an integer or returns a default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvDuration retrieves an environment variable as a duration or returns a default value
func getEnvDuration(key string, defaultValue string) time.Duration {
	value := getEnv(key, defaultValue)
	duration, err := time.ParseDuration(value)
	if err != nil {
		// If parsing fails, use the default
		duration, _ = time.ParseDuration(defaultValue)
	}
	return duration
}
