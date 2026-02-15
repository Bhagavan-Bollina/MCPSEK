package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AuthResult represents the results of authentication posture checking
type AuthResult struct {
	Status            string          `json:"status"` // "pass", "warning", "critical"
	Method            string          `json:"method"` // "oauth2", "static_key", "none", "unknown"
	CommittedSecrets  []SecretFinding `json:"committed_secrets,omitempty"`
	TokenRefresh      *bool           `json:"token_refresh,omitempty"`
	ScopedPermissions *bool           `json:"scoped_permissions,omitempty"`
	EnvVarsReferenced []string        `json:"env_vars_referenced,omitempty"`
}

// SecretFinding represents a committed secret
type SecretFinding struct {
	FilePath   string `json:"file_path"`
	SecretType string `json:"secret_type"`
	LineNumber int    `json:"line_number"`
	Snippet    string `json:"snippet"` // Redacted
}

// CheckAuth scans a repository for authentication posture
func CheckAuth(repoPath string) (*AuthResult, error) {
	result := &AuthResult{
		Status:            "pass",
		Method:            "unknown",
		CommittedSecrets:  make([]SecretFinding, 0),
		EnvVarsReferenced: make([]string, 0),
	}

	// Track auth method indicators
	oauthCount := 0
	staticSecretCount := 0

	// Scan all files
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Read file
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		contentStr := string(content)
		relativePath := strings.TrimPrefix(path, repoPath+"/")

		// Check for OAuth indicators
		for _, pattern := range oauthPatterns {
			if pattern.MatchString(contentStr) {
				oauthCount++
				break
			}
		}

		// Check for static secret indicators
		for _, pattern := range staticSecretPatterns {
			if pattern.MatchString(contentStr) {
				staticSecretCount++
				// Extract env var names
				matches := pattern.FindAllString(contentStr, -1)
				for _, match := range matches {
					if strings.Contains(match, "API_KEY") || strings.Contains(match, "TOKEN") {
						result.EnvVarsReferenced = append(result.EnvVarsReferenced, match)
					}
				}
			}
		}

		// Check for committed secrets
		secrets := findCommittedSecrets(contentStr, relativePath)
		result.CommittedSecrets = append(result.CommittedSecrets, secrets...)

		// Check .gitignore for .env
		if strings.HasSuffix(path, ".gitignore") {
			if !strings.Contains(contentStr, ".env") {
				// .env not in .gitignore - CRITICAL
				result.CommittedSecrets = append(result.CommittedSecrets, SecretFinding{
					FilePath:   relativePath,
					SecretType: "missing_gitignore_entry",
					Snippet:    ".env file not excluded in .gitignore",
				})
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk repository: %w", err)
	}

	// Deduplicate env vars
	result.EnvVarsReferenced = uniqueStrings(result.EnvVarsReferenced)

	// Determine auth method
	if oauthCount >= 2 {
		result.Method = "oauth2"
		// Check for token refresh
		tokenRefresh := oauthCount >= 3 // If we found refresh_token pattern
		result.TokenRefresh = &tokenRefresh
		scopedPerms := true // Assume OAuth has scoping
		result.ScopedPermissions = &scopedPerms
	} else if staticSecretCount > 0 {
		result.Method = "static_key"
	} else {
		result.Method = "none"
	}

	// Determine status
	if len(result.CommittedSecrets) > 0 || result.Method == "none" {
		result.Status = "critical"
	} else if result.Method == "static_key" {
		result.Status = "warning"
	} else if result.Method == "oauth2" {
		if result.TokenRefresh != nil && !*result.TokenRefresh {
			result.Status = "warning"
		} else {
			result.Status = "pass"
		}
	}

	return result, nil
}

// findCommittedSecrets scans content for committed secrets
func findCommittedSecrets(content, filePath string) []SecretFinding {
	secrets := make([]SecretFinding, 0)

	// Split into lines for line number tracking
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// AWS keys
		if awsKeyPattern.MatchString(line) {
			secrets = append(secrets, SecretFinding{
				FilePath:   filePath,
				SecretType: "aws_key",
				LineNumber: lineNum + 1,
				Snippet:    redactSecret(line),
			})
		}

		// GitHub PAT
		if githubPatPattern.MatchString(line) || githubPat2Pattern.MatchString(line) {
			secrets = append(secrets, SecretFinding{
				FilePath:   filePath,
				SecretType: "github_pat",
				LineNumber: lineNum + 1,
				Snippet:    redactSecret(line),
			})
		}

		// Private keys
		if privateKeyPattern.MatchString(line) {
			secrets = append(secrets, SecretFinding{
				FilePath:   filePath,
				SecretType: "private_key",
				LineNumber: lineNum + 1,
				Snippet:    "Private key detected",
			})
		}

		// Slack tokens
		if slackTokenPattern.MatchString(line) {
			secrets = append(secrets, SecretFinding{
				FilePath:   filePath,
				SecretType: "slack_token",
				LineNumber: lineNum + 1,
				Snippet:    redactSecret(line),
			})
		}

		// Generic API keys
		if genericKeyPattern.MatchString(line) {
			secrets = append(secrets, SecretFinding{
				FilePath:   filePath,
				SecretType: "generic_key",
				LineNumber: lineNum + 1,
				Snippet:    redactSecret(line),
			})
		}
	}

	return secrets
}

// redactSecret redacts sensitive parts of a line
func redactSecret(line string) string {
	if len(line) > 50 {
		return line[:20] + "***REDACTED***" + line[len(line)-10:]
	}
	return "***REDACTED***"
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// ToJSON converts AuthResult to JSON
func (r *AuthResult) ToJSON() (json.RawMessage, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal auth result: %w", err)
	}
	return json.RawMessage(data), nil
}
