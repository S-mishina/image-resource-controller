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

package registry

import (
	"context"
	"time"
)

// RegistryType represents the type of container registry
type RegistryType string

const (
	RegistryTypeECR       RegistryType = "ecr"
	RegistryTypeGCR       RegistryType = "gcr"
	RegistryTypeDockerHub RegistryType = "dockerhub"
	RegistryTypeHarbor    RegistryType = "harbor"
)

// ImageInfo represents information about a container image
type ImageInfo struct {
	// Name is the image name (e.g., "my-service")
	Name string

	// Tag is the image tag (e.g., "v1.2.3")
	Tag string

	// Digest is the image digest (e.g., "sha256:abc123...")
	Digest string

	// PushedAt is when the image was pushed to the registry
	PushedAt time.Time

	// FullURL is the complete image URL (e.g., "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3")
	FullURL string

	// Size is the image size in bytes (optional)
	Size int64

	// Architecture is the image architecture (e.g., "amd64", "arm64")
	Architecture string
}

// RegistryConfig represents configuration for accessing a registry
type RegistryConfig struct {
	// Type is the registry type
	Type RegistryType

	// RepositoryName is the repository to scan (e.g., "my-service" or "namespace/my-service")
	RepositoryName string

	// Region is the registry region (for cloud providers)
	Region string

	// RegistryURL is the registry URL (for custom registries)
	RegistryURL string

	// Namespace is the registry namespace (for some registries)
	Namespace string
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	// Type is the registry type (used to determine auth method)
	Type RegistryType

	// Username for basic auth
	Username string

	// Password for basic auth
	Password string

	// Token for token-based auth
	Token string

	// AWSConfig for AWS-specific authentication
	AWSConfig *AWSAuthConfig

	// GCPConfig for GCP-specific authentication
	GCPConfig *GCPAuthConfig
}

// AWSAuthConfig represents AWS-specific authentication
type AWSAuthConfig struct {
	// Region is the AWS region
	Region string

	// AccessKeyID for explicit credentials
	AccessKeyID string

	// SecretAccessKey for explicit credentials
	SecretAccessKey string

	// SessionToken for temporary credentials
	SessionToken string

	// RoleArn for role-based authentication
	RoleArn string

	// UseDefaultCredentials to use default credential chain
	UseDefaultCredentials bool
}

// GCPAuthConfig represents GCP-specific authentication
type GCPAuthConfig struct {
	// ProjectID is the GCP project ID
	ProjectID string

	// ServiceAccountJSON is the service account key JSON
	ServiceAccountJSON string

	// UseDefaultCredentials to use default credential chain
	UseDefaultCredentials bool
}

// ImageRegistry defines the interface for container registry operations
type ImageRegistry interface {
	// ScanRepository scans a repository and returns available images
	ScanRepository(ctx context.Context, config RegistryConfig) ([]ImageInfo, error)

	// ScanRepositoriesByPattern scans multiple repositories matching a pattern and returns all images
	ScanRepositoriesByPattern(ctx context.Context, region, pattern string, maxRepos int32) ([]ImageInfo, error)

	// FindRepositoriesByPattern finds repositories that match the given pattern
	FindRepositoriesByPattern(ctx context.Context, region, pattern string, maxRepos int32) ([]string, error)

	// ScanAllRepositoriesByImageName scans ALL repositories to find images matching the image name pattern
	ScanAllRepositoriesByImageName(ctx context.Context, region, imageNamePattern string, maxRepos int32) ([]ImageInfo, error)

	// ScanByImagePattern scans repositories by combined repository:tag pattern
	ScanByImagePattern(ctx context.Context, region, imagePattern string, maxRepos int32) ([]ImageInfo, error)

	// Authenticate performs authentication with the registry
	Authenticate(ctx context.Context, authConfig AuthConfig) error

	// GetRegistryType returns the registry type this implementation supports
	GetRegistryType() RegistryType

	// ValidateConfig validates the provided registry configuration
	ValidateConfig(config RegistryConfig) error

	// HealthCheck checks if the registry is accessible
	HealthCheck(ctx context.Context) error
}

// ScanOptions represents options for scanning repositories
type ScanOptions struct {
	// MaxImages limits the number of images returned
	MaxImages int

	// IncludeManifest whether to include manifest information
	IncludeManifest bool

	// TagFilter filters images by tag pattern
	TagFilter string

	// SinceTime only return images newer than this time
	SinceTime *time.Time
}

// ImageRegistryFactory creates registry implementations
type ImageRegistryFactory interface {
	// CreateRegistry creates a registry implementation based on config
	CreateRegistry(registryType RegistryType) (ImageRegistry, error)

	// GetSupportedTypes returns supported registry types
	GetSupportedTypes() []RegistryType
}
