/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package generic provides a Docker Registry HTTP API V2 client.
package generic

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RegistryTypeGeneric is the registry type constant for generic registry.
const RegistryTypeGeneric = "generic"

// ImageInfo represents information about a container image
type ImageInfo struct {
	Name         string
	Tag          string
	Digest       string
	PushedAt     time.Time
	FullURL      string
	Size         int64
	Architecture string
}

// RegistryConfig represents configuration for accessing a registry
type RegistryConfig struct {
	Type           string
	RepositoryName string
	Region         string
	RegistryURL    string
	Namespace      string
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type     string
	Username string
	Password string
	Token    string
}

// ImageRegistry defines the interface for container registry operations
type ImageRegistry interface {
	ScanRepository(ctx context.Context, config RegistryConfig) ([]ImageInfo, error)
	ScanRepositoriesByPattern(ctx context.Context, region, pattern string, maxRepos int32) ([]ImageInfo, error)
	FindRepositoriesByPattern(ctx context.Context, region, pattern string, maxRepos int32) ([]string, error)
	ScanAllRepositoriesByImageName(ctx context.Context, region, imageNamePattern string, maxRepos int32) ([]ImageInfo, error)
	ScanByImagePattern(ctx context.Context, region, imagePattern string, maxRepos int32) ([]ImageInfo, error)
	Authenticate(ctx context.Context, authConfig AuthConfig) error
	GetRegistryType() string
	ValidateConfig(config RegistryConfig) error
	HealthCheck(ctx context.Context) error
}

// GenericRegistry implements ImageRegistry for Docker Registry HTTP API V2.
//
//nolint:revive // stuttering name is acceptable for clarity
type GenericRegistry struct {
	httpClient  *http.Client
	registryURL string
	username    string
	password    string
}

// NewGenericRegistry creates a new GenericRegistry instance
func NewGenericRegistry() ImageRegistry {
	return &GenericRegistry{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetRegistryType returns the registry type
func (g *GenericRegistry) GetRegistryType() string {
	return RegistryTypeGeneric
}

// ValidateConfig validates generic registry configuration
func (g *GenericRegistry) ValidateConfig(config RegistryConfig) error {
	if config.Type != RegistryTypeGeneric {
		return fmt.Errorf("invalid registry type for generic: %s", config.Type)
	}
	if config.RegistryURL == "" {
		return fmt.Errorf("registryURL is required for generic registry")
	}
	if config.RepositoryName == "" {
		return fmt.Errorf("repositoryName is required for generic registry")
	}
	return nil
}

// Authenticate sets up authentication for the registry
func (g *GenericRegistry) Authenticate(_ context.Context, authConfig AuthConfig) error {
	if authConfig.Username != "" {
		g.username = authConfig.Username
		g.password = authConfig.Password
	}

	// Store registry URL from a well-known location if not set
	// The actual URL is set via config, not auth
	return nil
}

// SetRegistryURL sets the registry base URL
func (g *GenericRegistry) SetRegistryURL(url string) {
	g.registryURL = strings.TrimRight(url, "/")
}

// HealthCheck checks if the registry is accessible
func (g *GenericRegistry) HealthCheck(ctx context.Context) error {
	if g.registryURL == "" {
		return fmt.Errorf("registry URL not set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.registryURL+"/v2/", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	g.setAuth(req)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("registry health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry returned status %d", resp.StatusCode)
	}
	return nil
}

// ScanRepository scans a repository and returns available images
func (g *GenericRegistry) ScanRepository(ctx context.Context, config RegistryConfig) ([]ImageInfo, error) {
	if err := g.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	registryURL := strings.TrimRight(config.RegistryURL, "/")
	if g.registryURL == "" {
		g.registryURL = registryURL
	}

	// Get tags list
	tags, err := g.listTags(ctx, registryURL, config.RepositoryName)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags for %s: %w", config.RepositoryName, err)
	}

	// Build ImageInfo for each tag
	images := make([]ImageInfo, 0, len(tags))
	for _, tag := range tags {
		img := ImageInfo{
			Name:    config.RepositoryName,
			Tag:     tag,
			FullURL: fmt.Sprintf("%s/%s:%s", registryURL, config.RepositoryName, tag),
		}

		// Try to get manifest for digest and size
		digest, size, err := g.getManifestInfo(ctx, registryURL, config.RepositoryName, tag)
		if err == nil {
			img.Digest = digest
			img.Size = size
		}

		images = append(images, img)
	}

	return images, nil
}

// FindRepositoriesByPattern finds repositories matching a pattern
func (g *GenericRegistry) FindRepositoriesByPattern(ctx context.Context, _, pattern string, maxRepos int32) ([]string, error) {
	if g.registryURL == "" {
		return nil, fmt.Errorf("registry URL not set - call SetRegistryURL or ScanRepository first")
	}

	repos, err := g.listRepositories(ctx, g.registryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	var matched []string
	for _, repo := range repos {
		if matchWildcard(repo, pattern) {
			matched = append(matched, repo)
			if int32(len(matched)) >= maxRepos {
				break
			}
		}
	}

	return matched, nil
}

// ScanRepositoriesByPattern scans multiple repositories matching a pattern
func (g *GenericRegistry) ScanRepositoriesByPattern(ctx context.Context, region, pattern string, maxRepos int32) ([]ImageInfo, error) {
	repos, err := g.FindRepositoriesByPattern(ctx, region, pattern, maxRepos)
	if err != nil {
		return nil, err
	}

	var allImages []ImageInfo
	for _, repo := range repos {
		config := RegistryConfig{
			Type:           RegistryTypeGeneric,
			RepositoryName: repo,
			RegistryURL:    g.registryURL,
		}
		images, err := g.ScanRepository(ctx, config)
		if err != nil {
			continue
		}
		allImages = append(allImages, images...)
	}

	return allImages, nil
}

// ScanAllRepositoriesByImageName scans all repositories to find images matching image name
func (g *GenericRegistry) ScanAllRepositoriesByImageName(ctx context.Context, _, imageNamePattern string, maxRepos int32) ([]ImageInfo, error) {
	if g.registryURL == "" {
		return nil, fmt.Errorf("registry URL not set")
	}

	repos, err := g.listRepositories(ctx, g.registryURL)
	if err != nil {
		return nil, err
	}

	var matchingImages []ImageInfo
	scanned := int32(0)

	for _, repo := range repos {
		if scanned >= maxRepos {
			break
		}

		if !matchWildcard(repo, imageNamePattern) {
			continue
		}

		config := RegistryConfig{
			Type:           RegistryTypeGeneric,
			RepositoryName: repo,
			RegistryURL:    g.registryURL,
		}
		images, err := g.ScanRepository(ctx, config)
		if err != nil {
			continue
		}
		scanned++
		matchingImages = append(matchingImages, images...)
	}

	return matchingImages, nil
}

// ScanByImagePattern scans by combined repository:tag pattern
func (g *GenericRegistry) ScanByImagePattern(ctx context.Context, region, imagePattern string, maxRepos int32) ([]ImageInfo, error) {
	parts := strings.SplitN(imagePattern, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid image pattern format, expected 'repository:tag' but got '%s'", imagePattern)
	}
	repoPattern := parts[0]
	tagPattern := parts[1]

	repos, err := g.FindRepositoriesByPattern(ctx, region, repoPattern, maxRepos)
	if err != nil {
		return nil, err
	}

	var matchingImages []ImageInfo
	for _, repo := range repos {
		config := RegistryConfig{
			Type:           RegistryTypeGeneric,
			RepositoryName: repo,
			RegistryURL:    g.registryURL,
		}
		images, err := g.ScanRepository(ctx, config)
		if err != nil {
			continue
		}
		for _, img := range images {
			if matchWildcard(img.Tag, tagPattern) {
				matchingImages = append(matchingImages, img)
			}
		}
	}

	return matchingImages, nil
}

// Docker Registry HTTP API V2 response types

type catalogResponse struct {
	Repositories []string `json:"repositories"`
}

type tagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type manifestResponse struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}

// listRepositories calls GET /v2/_catalog
func (g *GenericRegistry) listRepositories(ctx context.Context, registryURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryURL+"/v2/_catalog", nil)
	if err != nil {
		return nil, err
	}
	g.setAuth(req)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog request returned status %d", resp.StatusCode)
	}

	var catalog catalogResponse
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("failed to decode catalog response: %w", err)
	}

	return catalog.Repositories, nil
}

// listTags calls GET /v2/<name>/tags/list
func (g *GenericRegistry) listTags(ctx context.Context, registryURL, repository string) ([]string, error) {
	url := fmt.Sprintf("%s/v2/%s/tags/list", registryURL, repository)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	g.setAuth(req)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags request returned status %d", resp.StatusCode)
	}

	var tagsResp tagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		return nil, fmt.Errorf("failed to decode tags response: %w", err)
	}

	return tagsResp.Tags, nil
}

// getManifestInfo calls GET /v2/<name>/manifests/<reference>
func (g *GenericRegistry) getManifestInfo(ctx context.Context, registryURL, repository, tag string) (string, int64, error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", registryURL, repository, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	g.setAuth(req)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("manifest request returned status %d", resp.StatusCode)
	}

	// Read body for digest calculation
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	// Use Docker-Content-Digest header if available, otherwise compute
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		hash := sha256.Sum256(body)
		digest = fmt.Sprintf("sha256:%x", hash)
	}

	// Parse manifest for total size
	var manifest manifestResponse
	if err := json.Unmarshal(body, &manifest); err != nil {
		return digest, 0, nil
	}

	var totalSize int64
	totalSize += manifest.Config.Size
	for _, layer := range manifest.Layers {
		totalSize += layer.Size
	}

	return digest, totalSize, nil
}

// setAuth adds authentication headers to a request
func (g *GenericRegistry) setAuth(req *http.Request) {
	if g.username != "" {
		req.SetBasicAuth(g.username, g.password)
	}
}

// matchWildcard implements simple wildcard matching
func matchWildcard(text, pattern string) bool {
	if pattern == text {
		return true
	}

	if !strings.Contains(pattern, "*") {
		return false
	}

	parts := strings.Split(pattern, "*")

	if len(parts) == 2 {
		prefix := parts[0]
		suffix := parts[1]
		if prefix != "" && !strings.HasPrefix(text, prefix) {
			return false
		}
		if suffix != "" && !strings.HasSuffix(text, suffix) {
			return false
		}
		if prefix != "" && suffix != "" {
			return len(text) >= len(prefix)+len(suffix)
		}
		return true
	}

	// Multi-wildcard: check prefix, suffix, and all middle parts
	if parts[0] != "" && !strings.HasPrefix(text, parts[0]) {
		return false
	}
	if parts[len(parts)-1] != "" && !strings.HasSuffix(text, parts[len(parts)-1]) {
		return false
	}
	for _, part := range parts[1 : len(parts)-1] {
		if part != "" && !strings.Contains(text, part) {
			return false
		}
	}
	return true
}
