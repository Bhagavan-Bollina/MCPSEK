package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Scan represents a security scan of an MCP server
type Scan struct {
	ID                     uuid.UUID       `json:"id"`
	ServerID               uuid.UUID       `json:"server_id"`
	ScannedAt              time.Time       `json:"scanned_at"`
	ToolIntegrityStatus    string          `json:"tool_integrity_status"`
	ToolIntegrityDetails   json.RawMessage `json:"tool_integrity_details"`
	AuthStatus             string          `json:"auth_status"`
	AuthDetails            json.RawMessage `json:"auth_details"`
	ExposureStatus         string          `json:"exposure_status"`
	ExposureDetails        json.RawMessage `json:"exposure_details"`
	TrustScore             int             `json:"trust_score"`
	ToolDefinitionsHash    *string         `json:"tool_definitions_hash,omitempty"`
	ScanDurationMs         *int            `json:"scan_duration_ms,omitempty"`
}

// InsertScan creates a new scan record
func (db *DB) InsertScan(ctx context.Context, scan *Scan) error {
	query := `
		INSERT INTO scans (
			server_id, tool_integrity_status, tool_integrity_details,
			auth_status, auth_details, exposure_status, exposure_details,
			trust_score, tool_definitions_hash, scan_duration_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, scanned_at
	`

	err := db.pool.QueryRow(ctx, query,
		scan.ServerID,
		scan.ToolIntegrityStatus,
		scan.ToolIntegrityDetails,
		scan.AuthStatus,
		scan.AuthDetails,
		scan.ExposureStatus,
		scan.ExposureDetails,
		scan.TrustScore,
		scan.ToolDefinitionsHash,
		scan.ScanDurationMs,
	).Scan(&scan.ID, &scan.ScannedAt)

	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	return nil
}

// GetScan retrieves a scan by ID
func (db *DB) GetScan(ctx context.Context, id uuid.UUID) (*Scan, error) {
	query := `
		SELECT id, server_id, scanned_at, tool_integrity_status, tool_integrity_details,
			   auth_status, auth_details, exposure_status, exposure_details,
			   trust_score, tool_definitions_hash, scan_duration_ms
		FROM scans
		WHERE id = $1
	`

	scan := &Scan{}
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&scan.ID, &scan.ServerID, &scan.ScannedAt,
		&scan.ToolIntegrityStatus, &scan.ToolIntegrityDetails,
		&scan.AuthStatus, &scan.AuthDetails,
		&scan.ExposureStatus, &scan.ExposureDetails,
		&scan.TrustScore, &scan.ToolDefinitionsHash, &scan.ScanDurationMs,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("scan not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get scan: %w", err)
	}

	return scan, nil
}

// GetLatestScanForServer retrieves the most recent scan for a server
func (db *DB) GetLatestScanForServer(ctx context.Context, serverID uuid.UUID) (*Scan, error) {
	query := `
		SELECT id, server_id, scanned_at, tool_integrity_status, tool_integrity_details,
			   auth_status, auth_details, exposure_status, exposure_details,
			   trust_score, tool_definitions_hash, scan_duration_ms
		FROM scans
		WHERE server_id = $1
		ORDER BY scanned_at DESC
		LIMIT 1
	`

	scan := &Scan{}
	err := db.pool.QueryRow(ctx, query, serverID).Scan(
		&scan.ID, &scan.ServerID, &scan.ScannedAt,
		&scan.ToolIntegrityStatus, &scan.ToolIntegrityDetails,
		&scan.AuthStatus, &scan.AuthDetails,
		&scan.ExposureStatus, &scan.ExposureDetails,
		&scan.TrustScore, &scan.ToolDefinitionsHash, &scan.ScanDurationMs,
	)

	if err == pgx.ErrNoRows {
		return nil, nil // No scans yet
	}
	if err != nil {
		return nil, fmt.Errorf("get latest scan: %w", err)
	}

	return scan, nil
}

// GetScanHistory retrieves scan history for a server
func (db *DB) GetScanHistory(ctx context.Context, serverID uuid.UUID, limit, offset int) ([]*Scan, int, error) {
	// Get total count
	var total int
	err := db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM scans WHERE server_id = $1", serverID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count scans: %w", err)
	}

	// Get paginated results
	query := `
		SELECT id, server_id, scanned_at, tool_integrity_status, tool_integrity_details,
			   auth_status, auth_details, exposure_status, exposure_details,
			   trust_score, tool_definitions_hash, scan_duration_ms
		FROM scans
		WHERE server_id = $1
		ORDER BY scanned_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := db.pool.Query(ctx, query, serverID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query scan history: %w", err)
	}
	defer rows.Close()

	scans := make([]*Scan, 0)
	for rows.Next() {
		scan := &Scan{}
		err := rows.Scan(
			&scan.ID, &scan.ServerID, &scan.ScannedAt,
			&scan.ToolIntegrityStatus, &scan.ToolIntegrityDetails,
			&scan.AuthStatus, &scan.AuthDetails,
			&scan.ExposureStatus, &scan.ExposureDetails,
			&scan.TrustScore, &scan.ToolDefinitionsHash, &scan.ScanDurationMs,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan row: %w", err)
		}
		scans = append(scans, scan)
	}

	return scans, total, nil
}

// GetRecentCriticalScans retrieves recently scanned servers with critical findings
func (db *DB) GetRecentCriticalScans(ctx context.Context, limit int) ([]*Scan, error) {
	query := `
		SELECT id, server_id, scanned_at, tool_integrity_status, tool_integrity_details,
			   auth_status, auth_details, exposure_status, exposure_details,
			   trust_score, tool_definitions_hash, scan_duration_ms
		FROM scans
		WHERE tool_integrity_status = 'critical'
		   OR auth_status = 'critical'
		   OR exposure_status = 'critical'
		ORDER BY scanned_at DESC
		LIMIT $1
	`

	rows, err := db.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query critical scans: %w", err)
	}
	defer rows.Close()

	scans := make([]*Scan, 0)
	for rows.Next() {
		scan := &Scan{}
		err := rows.Scan(
			&scan.ID, &scan.ServerID, &scan.ScannedAt,
			&scan.ToolIntegrityStatus, &scan.ToolIntegrityDetails,
			&scan.AuthStatus, &scan.AuthDetails,
			&scan.ExposureStatus, &scan.ExposureDetails,
			&scan.TrustScore, &scan.ToolDefinitionsHash, &scan.ScanDurationMs,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		scans = append(scans, scan)
	}

	return scans, nil
}

// GetStats retrieves global statistics
func (db *DB) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total servers
	var totalServers int
	err := db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM servers").Scan(&totalServers)
	if err != nil {
		return nil, fmt.Errorf("count servers: %w", err)
	}
	stats["total_servers"] = totalServers

	// Total scans
	var totalScans int
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM scans").Scan(&totalScans)
	if err != nil {
		return nil, fmt.Errorf("count scans: %w", err)
	}
	stats["total_scans"] = totalScans

	// Critical findings
	var criticalFindings int
	err = db.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM scans
		WHERE tool_integrity_status = 'critical'
		   OR auth_status = 'critical'
		   OR exposure_status = 'critical'
	`).Scan(&criticalFindings)
	if err != nil {
		return nil, fmt.Errorf("count critical findings: %w", err)
	}
	stats["critical_findings"] = criticalFindings

	// Mutations detected
	var totalMutations int
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM mutations").Scan(&totalMutations)
	if err != nil {
		return nil, fmt.Errorf("count mutations: %w", err)
	}
	stats["total_mutations"] = totalMutations

	// Average trust score
	var avgTrustScore float64
	err = db.pool.QueryRow(ctx, "SELECT COALESCE(AVG(trust_score), 0) FROM servers WHERE trust_score >= 0").Scan(&avgTrustScore)
	if err != nil {
		return nil, fmt.Errorf("calculate avg trust score: %w", err)
	}
	stats["avg_trust_score"] = avgTrustScore

	return stats, nil
}
