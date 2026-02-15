package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Mutation represents a change in a tool definition between scans
type Mutation struct {
	ID              uuid.UUID       `json:"id"`
	ServerID        uuid.UUID       `json:"server_id"`
	ToolName        string          `json:"tool_name"`
	OldHash         string          `json:"old_hash"`
	NewHash         string          `json:"new_hash"`
	OldDescription  *string         `json:"old_description,omitempty"`
	NewDescription  *string         `json:"new_description,omitempty"`
	OldParameters   json.RawMessage `json:"old_parameters,omitempty"`
	NewParameters   json.RawMessage `json:"new_parameters,omitempty"`
	Severity        string          `json:"severity"`
	SeverityReason  *string         `json:"severity_reason,omitempty"`
	DetectedAt      time.Time       `json:"detected_at"`
}

// InsertMutation creates a new mutation record
func (db *DB) InsertMutation(ctx context.Context, mutation *Mutation) error {
	query := `
		INSERT INTO mutations (
			server_id, tool_name, old_hash, new_hash,
			old_description, new_description, old_parameters, new_parameters,
			severity, severity_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, detected_at
	`

	err := db.pool.QueryRow(ctx, query,
		mutation.ServerID,
		mutation.ToolName,
		mutation.OldHash,
		mutation.NewHash,
		mutation.OldDescription,
		mutation.NewDescription,
		mutation.OldParameters,
		mutation.NewParameters,
		mutation.Severity,
		mutation.SeverityReason,
	).Scan(&mutation.ID, &mutation.DetectedAt)

	if err != nil {
		return fmt.Errorf("insert mutation: %w", err)
	}

	return nil
}

// GetMutationsForServer retrieves mutation history for a server
func (db *DB) GetMutationsForServer(ctx context.Context, serverID uuid.UUID, limit, offset int) ([]*Mutation, int, error) {
	// Get total count
	var total int
	err := db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM mutations WHERE server_id = $1", serverID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count mutations: %w", err)
	}

	// Get paginated results
	query := `
		SELECT id, server_id, tool_name, old_hash, new_hash,
			   old_description, new_description, old_parameters, new_parameters,
			   severity, severity_reason, detected_at
		FROM mutations
		WHERE server_id = $1
		ORDER BY detected_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := db.pool.Query(ctx, query, serverID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query mutations: %w", err)
	}
	defer rows.Close()

	mutations := make([]*Mutation, 0)
	for rows.Next() {
		mutation := &Mutation{}
		err := rows.Scan(
			&mutation.ID, &mutation.ServerID, &mutation.ToolName,
			&mutation.OldHash, &mutation.NewHash,
			&mutation.OldDescription, &mutation.NewDescription,
			&mutation.OldParameters, &mutation.NewParameters,
			&mutation.Severity, &mutation.SeverityReason, &mutation.DetectedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan mutation row: %w", err)
		}
		mutations = append(mutations, mutation)
	}

	return mutations, total, nil
}

// GetRecentMutations retrieves recent mutations across all servers
func (db *DB) GetRecentMutations(ctx context.Context, limit int) ([]*Mutation, error) {
	query := `
		SELECT id, server_id, tool_name, old_hash, new_hash,
			   old_description, new_description, old_parameters, new_parameters,
			   severity, severity_reason, detected_at
		FROM mutations
		ORDER BY detected_at DESC
		LIMIT $1
	`

	rows, err := db.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent mutations: %w", err)
	}
	defer rows.Close()

	mutations := make([]*Mutation, 0)
	for rows.Next() {
		mutation := &Mutation{}
		err := rows.Scan(
			&mutation.ID, &mutation.ServerID, &mutation.ToolName,
			&mutation.OldHash, &mutation.NewHash,
			&mutation.OldDescription, &mutation.NewDescription,
			&mutation.OldParameters, &mutation.NewParameters,
			&mutation.Severity, &mutation.SeverityReason, &mutation.DetectedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan mutation row: %w", err)
		}
		mutations = append(mutations, mutation)
	}

	return mutations, nil
}
