package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// IntegrityResult represents the results of tool integrity checking
type IntegrityResult struct {
	Status               string             `json:"status"` // "pass", "warning", "critical"
	ToolsFound           int                `json:"tools_found"`
	HiddenInstructions   []IntegrityFinding `json:"hidden_instructions,omitempty"`
	SuspiciousParameters []IntegrityFinding `json:"suspicious_parameters,omitempty"`
	LongDescriptions     []IntegrityFinding `json:"long_descriptions,omitempty"`
	CrossToolReferences  []IntegrityFinding `json:"cross_tool_references,omitempty"`
}

// IntegrityFinding represents a specific finding
type IntegrityFinding struct {
	ToolName       string `json:"tool_name"`
	PatternMatched string `json:"pattern_matched"`
	Snippet        string `json:"snippet"`
	Severity       string `json:"severity"` // "critical" or "warning"
}

// ToolDefinition represents an extracted tool
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Hash        string                 `json:"hash"` // SHA256 of normalized content
}

// CheckIntegrity scans a repository for tool definitions and poisoning indicators
func CheckIntegrity(repoPath string) (*IntegrityResult, []*ToolDefinition, error) {
	result := &IntegrityResult{
		Status:               "pass",
		HiddenInstructions:   make([]IntegrityFinding, 0),
		SuspiciousParameters: make([]IntegrityFinding, 0),
		LongDescriptions:     make([]IntegrityFinding, 0),
		CrossToolReferences:  make([]IntegrityFinding, 0),
	}

	tools := make([]*ToolDefinition, 0)

	// Walk the repository
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't read
		}

		// Skip directories
		if info.IsDir() {
			// Skip excluded directories
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file extension
		ext := filepath.Ext(path)
		if !scanExtensions[ext] {
			return nil
		}

		// Read file
		content, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}

		// Extract tools from this file
		fileTools := extractTools(string(content), ext)
		tools = append(tools, fileTools...)

		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("walk repository: %w", err)
	}

	result.ToolsFound = len(tools)

	// Scan each tool for poisoning indicators
	for _, tool := range tools {
		scanToolForPoison(tool, result)
	}

	// Determine overall status
	if len(result.HiddenInstructions) > 0 {
		result.Status = "critical"
	} else if len(result.SuspiciousParameters) > 0 || len(result.LongDescriptions) > 0 || len(result.CrossToolReferences) > 0 {
		result.Status = "warning"
	}

	return result, tools, nil
}

// extractTools extracts tool definitions from source code
func extractTools(content, fileExt string) []*ToolDefinition {
	tools := make([]*ToolDefinition, 0)

	switch fileExt {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs":
		tools = append(tools, extractTypeScriptTools(content)...)
	case ".py":
		tools = append(tools, extractPythonTools(content)...)
	case ".json", ".yaml", ".yml":
		// JSON/YAML tool definitions (less common, skip for MVP)
	}

	return tools
}

// extractTypeScriptTools extracts tools from TypeScript/JavaScript code
func extractTypeScriptTools(content string) []*ToolDefinition {
	tools := make([]*ToolDefinition, 0)

	// Pattern 1: server.tool("name", "description", ...)
	matches := toolDefServerToolPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			tools = append(tools, &ToolDefinition{
				Name:        match[1],
				Description: truncate(match[2], 2000),
				Hash:        computeHash(match[1], match[2]),
			})
		}
	}

	// Pattern 2: { name: "...", description: "..." }
	matches = toolDefObjectPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			tools = append(tools, &ToolDefinition{
				Name:        match[1],
				Description: truncate(match[2], 2000),
				Hash:        computeHash(match[1], match[2]),
			})
		}
	}

	// Pattern 3: Tool({ name: "...", description: "..." })
	matches = toolDefToolPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			tools = append(tools, &ToolDefinition{
				Name:        match[1],
				Description: truncate(match[2], 2000),
				Hash:        computeHash(match[1], match[2]),
			})
		}
	}

	return tools
}

// extractPythonTools extracts tools from Python code
func extractPythonTools(content string) []*ToolDefinition {
	tools := make([]*ToolDefinition, 0)

	// Pattern 1: @server.tool() decorator with docstring
	matches := pythonDecoratorPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			tools = append(tools, &ToolDefinition{
				Name:        match[1],
				Description: truncate(match[2], 2000),
				Hash:        computeHash(match[1], match[2]),
			})
		}
	}

	// Pattern 2: Tool(name="...", description="...")
	matches = pythonToolPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			tools = append(tools, &ToolDefinition{
				Name:        match[1],
				Description: truncate(match[2], 2000),
				Hash:        computeHash(match[1], match[2]),
			})
		}
	}

	return tools
}

// scanToolForPoison checks a tool definition for poisoning indicators
func scanToolForPoison(tool *ToolDefinition, result *IntegrityResult) {
	desc := tool.Description

	// CRITICAL: Hidden instruction tags
	if hiddenInstructionPattern.MatchString(desc) {
		matches := hiddenInstructionPattern.FindAllString(desc, -1)
		for _, match := range matches {
			result.HiddenInstructions = append(result.HiddenInstructions, IntegrityFinding{
				ToolName:       tool.Name,
				PatternMatched: "hidden_instruction_tag",
				Snippet:        truncate(match, 200),
				Severity:       "critical",
			})
		}
	}

	// CRITICAL: File exfiltration
	for _, pattern := range fileExfiltrationPatterns {
		if pattern.MatchString(desc) {
			match := pattern.FindString(desc)
			result.HiddenInstructions = append(result.HiddenInstructions, IntegrityFinding{
				ToolName:       tool.Name,
				PatternMatched: "file_exfiltration",
				Snippet:        truncate(match, 200),
				Severity:       "critical",
			})
			break
		}
	}

	// CRITICAL: Data exfiltration
	for _, pattern := range dataExfiltrationPatterns {
		if pattern.MatchString(desc) {
			match := pattern.FindString(desc)
			result.HiddenInstructions = append(result.HiddenInstructions, IntegrityFinding{
				ToolName:       tool.Name,
				PatternMatched: "data_exfiltration",
				Snippet:        truncate(match, 200),
				Severity:       "critical",
			})
			break
		}
	}

	// CRITICAL: Concealment instructions
	for _, pattern := range concealmentPatterns {
		if pattern.MatchString(desc) {
			match := pattern.FindString(desc)
			result.HiddenInstructions = append(result.HiddenInstructions, IntegrityFinding{
				ToolName:       tool.Name,
				PatternMatched: "concealment",
				Snippet:        truncate(match, 200),
				Severity:       "critical",
			})
			break
		}
	}

	// WARNING: Long descriptions
	if len(desc) > 500 {
		result.LongDescriptions = append(result.LongDescriptions, IntegrityFinding{
			ToolName:       tool.Name,
			PatternMatched: "long_description",
			Snippet:        fmt.Sprintf("Description length: %d characters", len(desc)),
			Severity:       "warning",
		})
	}

	// WARNING: Suspicious parameters
	if tool.Parameters != nil {
		for paramName := range tool.Parameters {
			if suspiciousParamPattern.MatchString(paramName) {
				result.SuspiciousParameters = append(result.SuspiciousParameters, IntegrityFinding{
					ToolName:       tool.Name,
					PatternMatched: "suspicious_parameter",
					Snippet:        fmt.Sprintf("Parameter: %s", paramName),
					Severity:       "warning",
				})
			}
		}
	}

	// WARNING: Cross-tool references
	if crossToolRefPattern.MatchString(desc) {
		match := crossToolRefPattern.FindString(desc)
		result.CrossToolReferences = append(result.CrossToolReferences, IntegrityFinding{
			ToolName:       tool.Name,
			PatternMatched: "cross_tool_reference",
			Snippet:        truncate(match, 200),
			Severity:       "warning",
		})
	}
}

// computeHash computes SHA256 hash of tool name + description
func computeHash(name, description string) string {
	content := name + ":" + description
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// truncate truncates a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ToJSON converts IntegrityResult to JSON
func (r *IntegrityResult) ToJSON() (json.RawMessage, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal integrity result: %w", err)
	}
	return json.RawMessage(data), nil
}
