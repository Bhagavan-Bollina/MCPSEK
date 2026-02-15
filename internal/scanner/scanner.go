package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mcpsek/mcpsek/internal/database"
)

// Scanner orchestrates security scanning of MCP servers
type Scanner struct {
	cloneManager *CloneManager
	db           *database.DB
}

// New creates a new scanner
func New(cloneDir string, db *database.DB) *Scanner {
	return &Scanner{
		cloneManager: NewCloneManager(cloneDir),
		db:           db,
	}
}

// ScanResult represents the complete scan results
type ScanResult struct {
	IntegrityResult *IntegrityResult
	AuthResult      *AuthResult
	ExposureResult  *ExposureResult
	TrustScore      int
	ToolDefinitions []*ToolDefinition
	ToolsHash       string
	Duration        time.Duration
}

// Scan performs a complete security scan of a server
func (s *Scanner) Scan(ctx context.Context, serverID uuid.UUID, repoURL string) (*ScanResult, error) {
	startTime := time.Now()

	// Clone repository
	repoPath, err := s.cloneManager.Clone(ctx, repoURL)
	if err != nil {
		return nil, fmt.Errorf("clone repository: %w", err)
	}

	// Run all three checks in parallel
	type checkResult struct {
		integrity *IntegrityResult
		auth      *AuthResult
		exposure  *ExposureResult
		tools     []*ToolDefinition
		err       error
	}

	resultChan := make(chan checkResult, 1)

	go func() {
		result := checkResult{}

		// Check 1: Tool Integrity
		integrity, tools, err := CheckIntegrity(repoPath)
		if err != nil {
			result.err = fmt.Errorf("integrity check: %w", err)
			resultChan <- result
			return
		}
		result.integrity = integrity
		result.tools = tools

		// Check 2: Authentication Posture
		auth, err := CheckAuth(repoPath)
		if err != nil {
			result.err = fmt.Errorf("auth check: %w", err)
			resultChan <- result
			return
		}
		result.auth = auth

		// Check 3: Endpoint Exposure
		exposure, err := CheckExposure(repoPath)
		if err != nil {
			result.err = fmt.Errorf("exposure check: %w", err)
			resultChan <- result
			return
		}
		result.exposure = exposure

		resultChan <- result
	}()

	// Wait for checks to complete
	var result checkResult
	select {
	case result = <-resultChan:
		if result.err != nil {
			return nil, result.err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Compute trust score
	trustScore := ComputeTrustScore(
		result.integrity.Status,
		result.auth.Status,
		result.exposure.Status,
	)

	// Compute tools hash
	toolsHash := computeToolsHash(result.tools)

	// Duration
	duration := time.Since(startTime)

	scanResult := &ScanResult{
		IntegrityResult: result.integrity,
		AuthResult:      result.auth,
		ExposureResult:  result.exposure,
		TrustScore:      trustScore,
		ToolDefinitions: result.tools,
		ToolsHash:       toolsHash,
		Duration:        duration,
	}

	// Store scan results in database
	if err := s.storeScanResults(ctx, serverID, scanResult); err != nil {
		return nil, fmt.Errorf("store scan results: %w", err)
	}

	return scanResult, nil
}

// storeScanResults saves scan results to the database
func (s *Scanner) storeScanResults(ctx context.Context, serverID uuid.UUID, result *ScanResult) error {
	// Convert results to JSON
	integrityJSON, err := result.IntegrityResult.ToJSON()
	if err != nil {
		return fmt.Errorf("convert integrity result: %w", err)
	}

	authJSON, err := result.AuthResult.ToJSON()
	if err != nil {
		return fmt.Errorf("convert auth result: %w", err)
	}

	exposureJSON, err := result.ExposureResult.ToJSON()
	if err != nil {
		return fmt.Errorf("convert exposure result: %w", err)
	}

	// Insert scan record
	scan := &database.Scan{
		ServerID:               serverID,
		ToolIntegrityStatus:    result.IntegrityResult.Status,
		ToolIntegrityDetails:   integrityJSON,
		AuthStatus:             result.AuthResult.Status,
		AuthDetails:            authJSON,
		ExposureStatus:         result.ExposureResult.Status,
		ExposureDetails:        exposureJSON,
		TrustScore:             result.TrustScore,
		ToolDefinitionsHash:    &result.ToolsHash,
		ScanDurationMs:         intPtr(int(result.Duration.Milliseconds())),
	}

	if err := s.db.InsertScan(ctx, scan); err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	// Insert tool definitions
	dbTools := make([]*database.ToolDefinition, len(result.ToolDefinitions))
	for i, tool := range result.ToolDefinitions {
		var params json.RawMessage
		if tool.Parameters != nil {
			params, _ = json.Marshal(tool.Parameters)
		}

		dbTools[i] = &database.ToolDefinition{
			ServerID:    serverID,
			ToolName:    tool.Name,
			Description: strPtr(tool.Description),
			Parameters:  params,
			ContentHash: tool.Hash,
		}
	}

	if err := s.db.InsertToolDefinitions(ctx, dbTools); err != nil {
		return fmt.Errorf("insert tool definitions: %w", err)
	}

	// Update server record
	transport := result.ExposureResult.Transport
	if err := s.db.UpdateServerAfterScan(ctx, serverID, result.TrustScore, len(result.ToolDefinitions), transport); err != nil {
		return fmt.Errorf("update server: %w", err)
	}

	// Check for mutations
	if err := s.detectMutations(ctx, serverID, result.ToolDefinitions); err != nil {
		// Log error but don't fail the scan
		fmt.Printf("Warning: mutation detection failed: %v\n", err)
	}

	return nil
}

// detectMutations compares current tools with previous scan to detect changes
func (s *Scanner) detectMutations(ctx context.Context, serverID uuid.UUID, currentTools []*ToolDefinition) error {
	// Get previous tool definitions
	previousTools, err := s.db.GetToolDefinitionsForServer(ctx, serverID)
	if err != nil {
		return err
	}

	// If no previous tools, nothing to compare
	if len(previousTools) == 0 {
		return nil
	}

	// Index previous tools by name
	prevMap := make(map[string]*database.ToolDefinition)
	for _, tool := range previousTools {
		prevMap[tool.ToolName] = tool
	}

	// Index current tools by name
	currMap := make(map[string]*ToolDefinition)
	for _, tool := range currentTools {
		currMap[tool.Name] = tool
	}

	// Detect mutations
	mutations := make([]*database.Mutation, 0)

	// Check for removed and modified tools
	for name, prevTool := range prevMap {
		if currTool, exists := currMap[name]; !exists {
			// Tool removed
			mutations = append(mutations, &database.Mutation{
				ServerID:       serverID,
				ToolName:       name,
				OldHash:        prevTool.ContentHash,
				NewHash:        "(removed)",
				OldDescription: prevTool.Description,
				Severity:       "warning",
				SeverityReason: strPtr("Tool was removed"),
			})
		} else if prevTool.ContentHash != currTool.Hash {
			// Tool modified
			severity, reason := assessMutationSeverity(prevTool.Description, strPtr(currTool.Description))

			var prevParams, currParams json.RawMessage
			prevParams = prevTool.Parameters
			if currTool.Parameters != nil {
				currParams, _ = json.Marshal(currTool.Parameters)
			}

			mutations = append(mutations, &database.Mutation{
				ServerID:       serverID,
				ToolName:       name,
				OldHash:        prevTool.ContentHash,
				NewHash:        currTool.Hash,
				OldDescription: prevTool.Description,
				NewDescription: strPtr(currTool.Description),
				OldParameters:  prevParams,
				NewParameters:  currParams,
				Severity:       severity,
				SeverityReason: strPtr(reason),
			})
		}
	}

	// Check for added tools
	for name, currTool := range currMap {
		if _, exists := prevMap[name]; !exists {
			mutations = append(mutations, &database.Mutation{
				ServerID:       serverID,
				ToolName:       name,
				OldHash:        "(none)",
				NewHash:        currTool.Hash,
				NewDescription: strPtr(currTool.Description),
				Severity:       "info",
				SeverityReason: strPtr("New tool added"),
			})
		}
	}

	// Insert mutation records
	for _, mutation := range mutations {
		if err := s.db.InsertMutation(ctx, mutation); err != nil {
			return err
		}
	}

	return nil
}

// assessMutationSeverity determines severity based on description changes
func assessMutationSeverity(oldDesc, newDesc *string) (string, string) {
	if oldDesc == nil || newDesc == nil {
		return "info", "Description changed"
	}

	oldLen := len(*oldDesc)
	newLen := len(*newDesc)

	// Check for suspicious indicators in new description
	if hiddenInstructionPattern.MatchString(*newDesc) {
		return "critical", "New description contains hidden instruction tags"
	}

	for _, pattern := range fileExfiltrationPatterns {
		if pattern.MatchString(*newDesc) && !pattern.MatchString(*oldDesc) {
			return "critical", "New description contains file exfiltration patterns"
		}
	}

	// Check for significant length increase
	if newLen > oldLen+200 {
		return "warning", fmt.Sprintf("Description grew by %d characters", newLen-oldLen)
	}

	return "info", "Minor description change"
}

// computeToolsHash computes a hash of all tool definitions
func computeToolsHash(tools []*ToolDefinition) string {
	if len(tools) == 0 {
		return ""
	}

	// Sort tools by name for consistent hashing
	sortedTools := make([]*ToolDefinition, len(tools))
	copy(sortedTools, tools)
	sort.Slice(sortedTools, func(i, j int) bool {
		return sortedTools[i].Name < sortedTools[j].Name
	})

	// Concatenate all hashes
	var builder strings.Builder
	for _, tool := range sortedTools {
		builder.WriteString(tool.Hash)
		builder.WriteString("|")
	}

	// Compute final hash
	hash := sha256.Sum256([]byte(builder.String()))
	return fmt.Sprintf("%x", hash)
}

// Helper functions
func intPtr(i int) *int {
	return &i
}

func strPtr(s string) *string {
	return &s
}
