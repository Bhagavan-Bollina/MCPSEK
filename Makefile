.PHONY: build run test db-setup db-reset clean

# Build the binary
build:
	@echo "Building mcpsek..."
	go build -o bin/mcpsek ./cmd/mcpsek

# Run the application
run:
	@echo "Running mcpsek..."
	go run ./cmd/mcpsek

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Setup database (assumes PostgreSQL is running)
db-setup:
	@echo "Setting up database..."
	createdb mcpsek || true
	psql -d mcpsek -f migrations/001_initial.sql

# Reset database (WARNING: destroys all data)
db-reset:
	@echo "Resetting database..."
	dropdb --if-exists mcpsek
	createdb mcpsek
	psql -d mcpsek -f migrations/001_initial.sql

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -rf /tmp/mcpsek-repos/

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	golangci-lint run || true
