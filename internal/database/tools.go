package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ToolDefinition represents a tool exposed by an MCP server
type ToolDefinition struct {
	ID          uuid.UUID       `json:"id"`
	ServerID    uuid.UUID       `json:"server_id"`
	ToolName    string          `json:"tool_name"`
	Description *string         `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	ContentHash string          `json:"content_hash"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
}

// InsertToolDefinitions inserts multiple tool definitions for a server
func (db *DB) InsertToolDefinitions(ctx context.Context, tools []*ToolDefinition) error {
	if len(tools) == 0 {
		return nil
	}

	return db.WithTransaction(ctx, func(tx pgx.Tx) error {
		for _, tool := range tools {
			query := `
				INSERT INTO tool_definitions (
					server_id, tool_name, description, parameters, content_hash
				) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (server_id, tool_name, content_hash)
				DO UPDATE SET last_seen = NOW()
				RETURNING id, first_seen, last_seen
			`

			err := tx.QueryRow(ctx, query,
				tool.ServerID,
				tool.ToolName,
				tool.Description,
				tool.Parameters,
				tool.ContentHash,
			).Scan(&tool.ID, &tool.FirstSeen, &tool.LastSeen)

			if err != nil {
				return fmt.Errorf("insert tool definition: %w", err)
			}
		}

		return nil
	})
}

// GetToolDefinitionsForServer retrieves all current tool definitions for a server
func (db *DB) GetToolDefinitionsForServer(ctx context.Context, serverID uuid.UUID) ([]*ToolDefinition, error) {
	query := `
		SELECT id, server_id, tool_name, description, parameters, content_hash, first_seen, last_seen
		FROM tool_definitions
		WHERE server_id = $1
		ORDER BY tool_name
	`

	rows, err := db.pool.Query(ctx, query, serverID)
	if err != nil {
		return nil, fmt.Errorf("query tool definitions: %w", err)
	}
	defer rows.Close()

	tools := make([]*ToolDefinition, 0)
	for rows.Next() {
		tool := &ToolDefinition{}
		err := rows.Scan(
			&tool.ID, &tool.ServerID, &tool.ToolName,
			&tool.Description, &tool.Parameters, &tool.ContentHash,
			&tool.FirstSeen, &tool.LastSeen,
		)
		if err != nil {
			return nil, fmt.Errorf("scan tool definition row: %w", err)
		}
		tools = append(tools, tool)
	}

	return tools, nil
}
