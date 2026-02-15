package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// ExposureResult represents the results of endpoint exposure checking
type ExposureResult struct {
	Status        string `json:"status"`         // "pass", "warning", "critical"
	Transport     string `json:"transport"`      // "stdio", "sse", "http", "websocket", "unknown"
	BindAddress   string `json:"bind_address"`   // "127.0.0.1", "0.0.0.0", or empty
	TLSConfigured *bool  `json:"tls_configured,omitempty"`
	DefaultPort   *int   `json:"default_port,omitempty"`
}

// CheckExposure scans a repository for endpoint exposure risks
func CheckExposure(repoPath string) (*ExposureResult, error) {
	result := &ExposureResult{
		Status:    "pass",
		Transport: "unknown",
	}

	// Track transport type indicators
	stdioCount := 0
	networkCount := 0
	hasBindAll := false
	hasBindLocalhost := false
	hasTLS := false
	var detectedPort *int

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

		// Only scan code files
		ext := filepath.Ext(path)
		if !scanExtensions[ext] {
			return nil
		}

		// Read file
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		contentStr := string(content)

		// Check for stdio indicators
		for _, pattern := range stdioPatterns {
			if pattern.MatchString(contentStr) {
				stdioCount++
				break
			}
		}

		// Check for network transport indicators
		for _, pattern := range networkTransportPatterns {
			if pattern.MatchString(contentStr) {
				networkCount++
				break
			}
		}

		// Check bind address
		if bindAllPattern.MatchString(contentStr) {
			hasBindAll = true
		}
		if bindLocalhostPattern.MatchString(contentStr) {
			hasBindLocalhost = true
		}

		// Check TLS
		for _, pattern := range tlsPatterns {
			if pattern.MatchString(contentStr) {
				hasTLS = true
				break
			}
		}

		// Extract port
		if matches := portPattern.FindStringSubmatch(contentStr); len(matches) > 0 {
			for i := 1; i < len(matches); i++ {
				if matches[i] != "" {
					if port, err := strconv.Atoi(matches[i]); err == nil {
						detectedPort = &port
						break
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk repository: %w", err)
	}

	// Determine transport type
	if networkCount > stdioCount {
		// Network transport detected
		if networkCount > 0 {
			result.Transport = "http" // Generic HTTP/SSE
		}
	} else if stdioCount > 0 {
		result.Transport = "stdio"
	}

	// Set bind address if network transport
	if result.Transport == "http" || result.Transport == "sse" || result.Transport == "websocket" {
		if hasBindAll {
			result.BindAddress = "0.0.0.0"
		} else if hasBindLocalhost {
			result.BindAddress = "127.0.0.1"
		}
		result.TLSConfigured = &hasTLS
		result.DefaultPort = detectedPort
	}

	// Determine status
	if result.Transport == "stdio" {
		result.Status = "pass"
	} else if result.Transport == "http" || result.Transport == "sse" || result.Transport == "websocket" {
		// Network transport - check for risks
		if hasBindAll && !hasTLS {
			result.Status = "critical" // Exposed to internet without TLS
		} else if hasBindAll || !hasTLS {
			result.Status = "warning" // Either exposed OR no TLS
		} else {
			result.Status = "pass" // Localhost + TLS
		}
	}

	return result, nil
}

// ToJSON converts ExposureResult to JSON
func (r *ExposureResult) ToJSON() (json.RawMessage, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal exposure result: %w", err)
	}
	return json.RawMessage(data), nil
}
