package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Server represents an MCP server
type Server struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	SourceURL       string     `json:"source_url"`
	PackageRegistry *string    `json:"package_registry,omitempty"`
	PackageName     *string    `json:"package_name,omitempty"`
	Description     *string    `json:"description,omitempty"`
	Author          *string    `json:"author,omitempty"`
	License         *string    `json:"license,omitempty"`
	Stars           int        `json:"stars"`
	Transport       *string    `json:"transport,omitempty"`
	ToolsCount      int        `json:"tools_count"`
	TrustScore      int        `json:"trust_score"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastScanned     *time.Time `json:"last_scanned,omitempty"`
	ScanStatus      string     `json:"scan_status"`
	ScanError       *string    `json:"scan_error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// UpsertServer inserts or updates a server (dedup by source_url)
func (db *DB) UpsertServer(ctx context.Context, server *Server) error {
	query := `
		INSERT INTO servers (
			name, source_url, package_registry, package_name,
			description, author, license, stars
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (source_url)
		DO UPDATE SET
			name = EXCLUDED.name,
			package_registry = EXCLUDED.package_registry,
			package_name = EXCLUDED.package_name,
			description = EXCLUDED.description,
			author = EXCLUDED.author,
			license = EXCLUDED.license,
			stars = EXCLUDED.stars,
			updated_at = NOW()
		RETURNING id, created_at, updated_at, first_seen, scan_status, trust_score, tools_count
	`

	err := db.pool.QueryRow(ctx, query,
		server.Name,
		server.SourceURL,
		server.PackageRegistry,
		server.PackageName,
		server.Description,
		server.Author,
		server.License,
		server.Stars,
	).Scan(&server.ID, &server.CreatedAt, &server.UpdatedAt, &server.FirstSeen, &server.ScanStatus, &server.TrustScore, &server.ToolsCount)

	if err != nil {
		return fmt.Errorf("upsert server: %w", err)
	}

	return nil
}

// GetServer retrieves a server by ID
func (db *DB) GetServer(ctx context.Context, id uuid.UUID) (*Server, error) {
	query := `
		SELECT id, name, source_url, package_registry, package_name,
			   description, author, license, stars, transport, tools_count,
			   trust_score, first_seen, last_scanned, scan_status, scan_error,
			   created_at, updated_at
		FROM servers
		WHERE id = $1
	`

	server := &Server{}
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&server.ID, &server.Name, &server.SourceURL, &server.PackageRegistry,
		&server.PackageName, &server.Description, &server.Author, &server.License,
		&server.Stars, &server.Transport, &server.ToolsCount, &server.TrustScore,
		&server.FirstSeen, &server.LastScanned, &server.ScanStatus, &server.ScanError,
		&server.CreatedAt, &server.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("server not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get server: %w", err)
	}

	return server, nil
}

// ListServers retrieves servers with pagination
func (db *DB) ListServers(ctx context.Context, limit, offset int) ([]*Server, int, error) {
	// Get total count
	var total int
	err := db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM servers").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count servers: %w", err)
	}

	// Get paginated results
	query := `
		SELECT id, name, source_url, package_registry, package_name,
			   description, author, license, stars, transport, tools_count,
			   trust_score, first_seen, last_scanned, scan_status, scan_error,
			   created_at, updated_at
		FROM servers
		ORDER BY trust_score DESC, created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := db.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query servers: %w", err)
	}
	defer rows.Close()

	servers := make([]*Server, 0)
	for rows.Next() {
		server := &Server{}
		err := rows.Scan(
			&server.ID, &server.Name, &server.SourceURL, &server.PackageRegistry,
			&server.PackageName, &server.Description, &server.Author, &server.License,
			&server.Stars, &server.Transport, &server.ToolsCount, &server.TrustScore,
			&server.FirstSeen, &server.LastScanned, &server.ScanStatus, &server.ScanError,
			&server.CreatedAt, &server.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan server row: %w", err)
		}
		servers = append(servers, server)
	}

	return servers, total, nil
}

// SearchServers performs full-text search on servers
func (db *DB) SearchServers(ctx context.Context, query string, limit, offset int) ([]*Server, int, error) {
	// Get total count for search
	var total int
	countQuery := `
		SELECT COUNT(*) FROM servers
		WHERE to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, ''))
		@@ plainto_tsquery('english', $1)
	`
	err := db.pool.QueryRow(ctx, countQuery, query).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search results: %w", err)
	}

	// Get paginated search results
	searchQuery := `
		SELECT id, name, source_url, package_registry, package_name,
			   description, author, license, stars, transport, tools_count,
			   trust_score, first_seen, last_scanned, scan_status, scan_error,
			   created_at, updated_at
		FROM servers
		WHERE to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, ''))
		@@ plainto_tsquery('english', $1)
		ORDER BY trust_score DESC, created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := db.pool.Query(ctx, searchQuery, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search servers: %w", err)
	}
	defer rows.Close()

	servers := make([]*Server, 0)
	for rows.Next() {
		server := &Server{}
		err := rows.Scan(
			&server.ID, &server.Name, &server.SourceURL, &server.PackageRegistry,
			&server.PackageName, &server.Description, &server.Author, &server.License,
			&server.Stars, &server.Transport, &server.ToolsCount, &server.TrustScore,
			&server.FirstSeen, &server.LastScanned, &server.ScanStatus, &server.ScanError,
			&server.CreatedAt, &server.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan server row: %w", err)
		}
		servers = append(servers, server)
	}

	return servers, total, nil
}

// UpdateServerScanStatus updates the scan status of a server
func (db *DB) UpdateServerScanStatus(ctx context.Context, id uuid.UUID, status string, errorMsg *string) error {
	query := `
		UPDATE servers
		SET scan_status = $1, scan_error = $2, updated_at = NOW()
		WHERE id = $3
	`
	err := db.Exec(ctx, query, status, errorMsg, id)
	if err != nil {
		return fmt.Errorf("update server scan status: %w", err)
	}
	return nil
}

// UpdateServerAfterScan updates server fields after a successful scan
func (db *DB) UpdateServerAfterScan(ctx context.Context, id uuid.UUID, trustScore, toolsCount int, transport string) error {
	query := `
		UPDATE servers
		SET trust_score = $1, tools_count = $2, transport = $3,
		    last_scanned = NOW(), scan_status = 'completed', scan_error = NULL, updated_at = NOW()
		WHERE id = $4
	`
	err := db.Exec(ctx, query, trustScore, toolsCount, transport, id)
	if err != nil {
		return fmt.Errorf("update server after scan: %w", err)
	}
	return nil
}

// GetServersToScan retrieves servers that need scanning
func (db *DB) GetServersToScan(ctx context.Context, limit int) ([]*Server, error) {
	query := `
		SELECT id, name, source_url, package_registry, package_name,
			   description, author, license, stars, transport, tools_count,
			   trust_score, first_seen, last_scanned, scan_status, scan_error,
			   created_at, updated_at
		FROM servers
		WHERE scan_status = 'pending'
		   OR (scan_status = 'completed' AND last_scanned < NOW() - INTERVAL '24 hours')
		   OR (scan_status = 'failed' AND last_scanned < NOW() - INTERVAL '7 days')
		ORDER BY
			CASE
				WHEN scan_status = 'pending' THEN 1
				WHEN scan_status = 'completed' THEN 2
				ELSE 3
			END,
			last_scanned ASC NULLS FIRST
		LIMIT $1
	`

	rows, err := db.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query servers to scan: %w", err)
	}
	defer rows.Close()

	servers := make([]*Server, 0)
	for rows.Next() {
		server := &Server{}
		err := rows.Scan(
			&server.ID, &server.Name, &server.SourceURL, &server.PackageRegistry,
			&server.PackageName, &server.Description, &server.Author, &server.License,
			&server.Stars, &server.Transport, &server.ToolsCount, &server.TrustScore,
			&server.FirstSeen, &server.LastScanned, &server.ScanStatus, &server.ScanError,
			&server.CreatedAt, &server.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan server row: %w", err)
		}
		servers = append(servers, server)
	}

	return servers, nil
}
