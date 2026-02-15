package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CloneManager handles git repository cloning and caching
type CloneManager struct {
	baseDir string
}

// NewCloneManager creates a new clone manager
func NewCloneManager(baseDir string) *CloneManager {
	return &CloneManager{baseDir: baseDir}
}

// Clone clones a repository or updates it if already cached
func (cm *CloneManager) Clone(ctx context.Context, repoURL string) (string, error) {
	// Parse org and repo from URL
	org, repo, err := parseRepoURL(repoURL)
	if err != nil {
		return "", fmt.Errorf("parse repo URL: %w", err)
	}

	targetDir := filepath.Join(cm.baseDir, org, repo)

	// Check if already cloned
	if _, err := os.Stat(filepath.Join(targetDir, ".git")); err == nil {
		// Already exists - do a pull
		if err := cm.pullRepo(ctx, targetDir); err != nil {
			// If pull fails, remove and re-clone
			os.RemoveAll(targetDir)
			return cm.cloneRepo(ctx, repoURL, targetDir)
		}
		return targetDir, nil
	}

	// Clone fresh
	return cm.cloneRepo(ctx, repoURL, targetDir)
}

// cloneRepo performs a shallow git clone
func (cm *CloneManager) cloneRepo(ctx context.Context, repoURL, targetDir string) (string, error) {
	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}

	// Set timeout for clone operation
	cloneCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Shallow clone to save time and space
	cmd := exec.CommandContext(cloneCtx, "git", "clone", "--depth", "1", "--single-branch", repoURL, targetDir)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git clone failed: %w", err)
	}

	// Check repo size - skip if > 500MB
	size, err := getDirSize(targetDir)
	if err == nil && size > 500*1024*1024 {
		os.RemoveAll(targetDir)
		return "", fmt.Errorf("repository too large: %d MB (max 500 MB)", size/(1024*1024))
	}

	return targetDir, nil
}

// pullRepo updates an existing repository
func (cm *CloneManager) pullRepo(ctx context.Context, repoDir string) error {
	pullCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(pullCtx, "git", "pull", "--ff-only")
	cmd.Dir = repoDir
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git pull failed: %w", err)
	}

	return nil
}

// parseRepoURL extracts org and repo name from GitHub URL
func parseRepoURL(url string) (org, repo string, err error) {
	// Handle various GitHub URL formats:
	// https://github.com/org/repo
	// https://github.com/org/repo.git
	// git@github.com:org/repo.git

	url = strings.TrimSpace(url)
	url = strings.TrimSuffix(url, ".git")

	if strings.HasPrefix(url, "https://github.com/") {
		parts := strings.Split(strings.TrimPrefix(url, "https://github.com/"), "/")
		if len(parts) >= 2 {
			return parts[0], parts[1], nil
		}
	} else if strings.HasPrefix(url, "git@github.com:") {
		parts := strings.Split(strings.TrimPrefix(url, "git@github.com:"), "/")
		if len(parts) >= 2 {
			return parts[0], parts[1], nil
		}
	}

	return "", "", fmt.Errorf("unsupported repository URL format: %s", url)
}

// getDirSize calculates the total size of a directory
func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// Cleanup removes old cloned repositories
func (cm *CloneManager) Cleanup() error {
	// TODO: Implement LRU cache eviction when needed
	// For MVP, this is a manual operation
	return nil
}
