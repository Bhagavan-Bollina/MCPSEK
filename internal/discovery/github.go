package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GitHubDiscoverer discovers MCP servers from GitHub
type GitHubDiscoverer struct {
	client *http.Client
	token  string
}

// NewGitHubDiscoverer creates a new GitHub discoverer
func NewGitHubDiscoverer(token string) *GitHubDiscoverer {
	return &GitHubDiscoverer{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		token: token,
	}
}

// Discover searches GitHub for MCP server repositories
func (d *GitHubDiscoverer) Discover(ctx context.Context) ([]*DiscoveredServer, error) {
	servers := make([]*DiscoveredServer, 0)

	// Search queries
	queries := []string{
		"topic:mcp-server",
		"topic:model-context-protocol",
		"mcp server in:name,description",
	}

	for _, query := range queries {
		results, err := d.searchGitHub(ctx, query)
		if err != nil {
			fmt.Printf("GitHub search error for '%s': %v\n", query, err)
			continue
		}
		servers = append(servers, results...)
	}

	return deduplicateServers(servers), nil
}

// searchGitHub performs a repository search on GitHub
func (d *GitHubDiscoverer) searchGitHub(ctx context.Context, query string) ([]*DiscoveredServer, error) {
	searchURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=updated&per_page=100", query)

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication if token is provided
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github search returned status %d", resp.StatusCode)
	}

	var result struct {
		Items []struct {
			Name        string `json:"name"`
			FullName    string `json:"full_name"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
			Owner       struct {
				Login string `json:"login"`
			} `json:"owner"`
			StargazersCount int    `json:"stargazers_count"`
			License         *struct {
				Name string `json:"name"`
			} `json:"license"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	servers := make([]*DiscoveredServer, 0)

	for _, item := range result.Items {
		var license *string
		if item.License != nil {
			license = &item.License.Name
		}

		servers = append(servers, &DiscoveredServer{
			Name:        item.FullName,
			SourceURL:   item.HTMLURL,
			Description: &item.Description,
			Author:      &item.Owner.Login,
			License:     license,
			Stars:       item.StargazersCount,
		})
	}

	return servers, nil
}
