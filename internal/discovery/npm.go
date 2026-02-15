package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NPMDiscoverer discovers MCP servers from npm registry
type NPMDiscoverer struct {
	client *http.Client
}

// NewNPMDiscoverer creates a new npm discoverer
func NewNPMDiscoverer() *NPMDiscoverer {
	return &NPMDiscoverer{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Discover searches npm for MCP-related packages
func (d *NPMDiscoverer) Discover(ctx context.Context) ([]*DiscoveredServer, error) {
	servers := make([]*DiscoveredServer, 0)

	// Search queries
	queries := []string{
		"mcp server",
		"model context protocol",
		"mcp-server",
		"@modelcontextprotocol",
	}

	for _, query := range queries {
		results, err := d.searchNPM(ctx, query)
		if err != nil {
			// Log error but continue with other queries
			fmt.Printf("NPM search error for '%s': %v\n", query, err)
			continue
		}
		servers = append(servers, results...)
	}

	// Deduplicate by source URL
	return deduplicateServers(servers), nil
}

// searchNPM performs a search on npm registry
func (d *NPMDiscoverer) searchNPM(ctx context.Context, query string) ([]*DiscoveredServer, error) {
	searchURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=%s&size=250", url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("npm search returned status %d", resp.StatusCode)
	}

	var result struct {
		Objects []struct {
			Package struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Links       struct {
					Repository string `json:"repository"`
				} `json:"links"`
				Author struct {
					Name string `json:"name"`
				} `json:"author"`
				Publisher struct {
					Username string `json:"username"`
				} `json:"publisher"`
			} `json:"package"`
		} `json:"objects"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	servers := make([]*DiscoveredServer, 0)
	registry := "npm"

	for _, obj := range result.Objects {
		pkg := obj.Package

		// Extract repository URL
		repoURL := pkg.Links.Repository
		if repoURL == "" {
			continue
		}

		// Normalize GitHub URL
		repoURL = normalizeGitHubURL(repoURL)
		if repoURL == "" {
			continue
		}

		author := pkg.Author.Name
		if author == "" {
			author = pkg.Publisher.Username
		}

		servers = append(servers, &DiscoveredServer{
			Name:            pkg.Name,
			SourceURL:       repoURL,
			PackageRegistry: &registry,
			PackageName:     &pkg.Name,
			Description:     &pkg.Description,
			Author:          &author,
		})
	}

	return servers, nil
}

// normalizeGitHubURL converts various GitHub URL formats to canonical form
func normalizeGitHubURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)

	// Handle git:// URLs
	if strings.HasPrefix(rawURL, "git://") {
		rawURL = strings.Replace(rawURL, "git://", "https://", 1)
	}

	// Handle git+https://
	if strings.HasPrefix(rawURL, "git+") {
		rawURL = strings.TrimPrefix(rawURL, "git+")
	}

	// Handle git@github.com:
	if strings.HasPrefix(rawURL, "git@github.com:") {
		rawURL = "https://github.com/" + strings.TrimPrefix(rawURL, "git@github.com:")
	}

	// Remove .git suffix
	rawURL = strings.TrimSuffix(rawURL, ".git")

	// Ensure it's a GitHub URL
	if !strings.Contains(rawURL, "github.com") {
		return ""
	}

	return rawURL
}

// deduplicateServers removes duplicate servers by source URL
func deduplicateServers(servers []*DiscoveredServer) []*DiscoveredServer {
	seen := make(map[string]bool)
	result := make([]*DiscoveredServer, 0)

	for _, server := range servers {
		if !seen[server.SourceURL] {
			seen[server.SourceURL] = true
			result = append(result, server)
		}
	}

	return result
}
