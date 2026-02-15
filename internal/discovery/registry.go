package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// RegistryDiscoverer discovers MCP servers from official MCP registry
type RegistryDiscoverer struct {
	client *http.Client
}

// NewRegistryDiscoverer creates a new registry discoverer
func NewRegistryDiscoverer() *RegistryDiscoverer {
	return &RegistryDiscoverer{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Discover fetches servers from the official MCP registry
func (d *RegistryDiscoverer) Discover(ctx context.Context) ([]*DiscoveredServer, error) {
	registryURL := "https://registry.modelcontextprotocol.io/v0/servers"

	req, err := http.NewRequestWithContext(ctx, "GET", registryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		// Registry might not exist yet - not an error
		return []*DiscoveredServer{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// Registry endpoint not available
		return []*DiscoveredServer{}, nil
	}

	var result struct {
		Servers []struct {
			Name        string `json:"name"`
			Repository  string `json:"repository"`
			Description string `json:"description"`
			Author      string `json:"author"`
			License     string `json:"license"`
		} `json:"servers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	servers := make([]*DiscoveredServer, 0)
	registry := "registry"

	for _, item := range result.Servers {
		repoURL := normalizeGitHubURL(item.Repository)
		if repoURL == "" {
			continue
		}

		servers = append(servers, &DiscoveredServer{
			Name:            item.Name,
			SourceURL:       repoURL,
			PackageRegistry: &registry,
			Description:     &item.Description,
			Author:          &item.Author,
			License:         &item.License,
		})
	}

	return servers, nil
}
