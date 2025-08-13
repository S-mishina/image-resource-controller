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
	"fmt"

	"github.com/S-mishina/image-resource-controller/internal/registry/ecr"
)

// Convert ECR types to registry types for compatibility
func ecrToRegistryImageInfo(ecrImages []ecr.ImageInfo) []ImageInfo {
	images := make([]ImageInfo, len(ecrImages))
	for i, img := range ecrImages {
		images[i] = ImageInfo{
			Name:         img.Name,
			Tag:          img.Tag,
			Digest:       img.Digest,
			PushedAt:     img.PushedAt,
			FullURL:      img.FullURL,
			Size:         img.Size,
			Architecture: img.Architecture,
		}
	}
	return images
}

// ECRRegistryAdapter adapts ECR registry to the common interface
type ECRRegistryAdapter struct {
	ecrRegistry ecr.ImageRegistry
}

func NewECRRegistryAdapter() ImageRegistry {
	return &ECRRegistryAdapter{
		ecrRegistry: ecr.NewECRRegistry(),
	}
}

func (a *ECRRegistryAdapter) ScanRepository(ctx context.Context, config RegistryConfig) ([]ImageInfo, error) {
	ecrConfig := ecr.RegistryConfig{
		Type:           ecr.RegistryType(config.Type),
		RepositoryName: config.RepositoryName,
		Region:         config.Region,
		RegistryURL:    config.RegistryURL,
		Namespace:      config.Namespace,
	}

	ecrImages, err := a.ecrRegistry.ScanRepository(ctx, ecrConfig)
	if err != nil {
		return nil, err
	}

	return ecrToRegistryImageInfo(ecrImages), nil
}

func (a *ECRRegistryAdapter) Authenticate(ctx context.Context, authConfig AuthConfig) error {
	ecrAuthConfig := ecr.AuthConfig{
		Type:     ecr.RegistryType(authConfig.Type),
		Username: authConfig.Username,
		Password: authConfig.Password,
		Token:    authConfig.Token,
	}
	if authConfig.AWSConfig != nil {
		ecrAuthConfig.AWSConfig = &ecr.AWSAuthConfig{
			Region:                authConfig.AWSConfig.Region,
			AccessKeyID:           authConfig.AWSConfig.AccessKeyID,
			SecretAccessKey:       authConfig.AWSConfig.SecretAccessKey,
			SessionToken:          authConfig.AWSConfig.SessionToken,
			RoleArn:               authConfig.AWSConfig.RoleArn,
			UseDefaultCredentials: authConfig.AWSConfig.UseDefaultCredentials,
		}
	}
	return a.ecrRegistry.Authenticate(ctx, ecrAuthConfig)
}

func (a *ECRRegistryAdapter) GetRegistryType() RegistryType {
	return RegistryType(a.ecrRegistry.GetRegistryType())
}

func (a *ECRRegistryAdapter) ValidateConfig(config RegistryConfig) error {
	ecrConfig := ecr.RegistryConfig{
		Type:           ecr.RegistryType(config.Type),
		RepositoryName: config.RepositoryName,
		Region:         config.Region,
		RegistryURL:    config.RegistryURL,
		Namespace:      config.Namespace,
	}
	return a.ecrRegistry.ValidateConfig(ecrConfig)
}

func (a *ECRRegistryAdapter) HealthCheck(ctx context.Context) error {
	return a.ecrRegistry.HealthCheck(ctx)
}

func (a *ECRRegistryAdapter) ScanRepositoriesByPattern(ctx context.Context, region, pattern string, maxRepos int32) ([]ImageInfo, error) {
	ecrImages, err := a.ecrRegistry.ScanRepositoriesByPattern(ctx, region, pattern, maxRepos)
	if err != nil {
		return nil, err
	}
	return ecrToRegistryImageInfo(ecrImages), nil
}

func (a *ECRRegistryAdapter) FindRepositoriesByPattern(ctx context.Context, region, pattern string, maxRepos int32) ([]string, error) {
	return a.ecrRegistry.FindRepositoriesByPattern(ctx, region, pattern, maxRepos)
}

func (a *ECRRegistryAdapter) ScanAllRepositoriesByImageName(ctx context.Context, region, imageNamePattern string, maxRepos int32) ([]ImageInfo, error) {
	ecrImages, err := a.ecrRegistry.ScanAllRepositoriesByImageName(ctx, region, imageNamePattern, maxRepos)
	if err != nil {
		return nil, err
	}
	return ecrToRegistryImageInfo(ecrImages), nil
}

func (a *ECRRegistryAdapter) ScanByImagePattern(ctx context.Context, region, imagePattern string, maxRepos int32) ([]ImageInfo, error) {
	ecrImages, err := a.ecrRegistry.ScanByImagePattern(ctx, region, imagePattern, maxRepos)
	if err != nil {
		return nil, err
	}
	return ecrToRegistryImageInfo(ecrImages), nil
}

// DefaultFactory is the default implementation of ImageRegistryFactory
type DefaultFactory struct {
	registries map[RegistryType]func() ImageRegistry
}

// NewDefaultFactory creates a new DefaultFactory with built-in registry support
func NewDefaultFactory() ImageRegistryFactory {
	factory := &DefaultFactory{
		registries: make(map[RegistryType]func() ImageRegistry),
	}

	// Register built-in registry implementations
	factory.RegisterRegistry(RegistryTypeECR, func() ImageRegistry {
		return NewECRRegistryAdapter()
	})

	// NOTE: Future registry implementations can be added here
	// factory.RegisterRegistry(RegistryTypeGCR, func() ImageRegistry {
	//     return gcr.NewGCRRegistry()
	// })
	// factory.RegisterRegistry(RegistryTypeDockerHub, func() ImageRegistry {
	//     return dockerhub.NewDockerHubRegistry()
	// })

	return factory
}

// RegisterRegistry registers a new registry implementation
func (f *DefaultFactory) RegisterRegistry(registryType RegistryType, constructor func() ImageRegistry) {
	f.registries[registryType] = constructor
}

// CreateRegistry creates a registry implementation based on the registry type
func (f *DefaultFactory) CreateRegistry(registryType RegistryType) (ImageRegistry, error) {
	constructor, exists := f.registries[registryType]
	if !exists {
		return nil, fmt.Errorf("unsupported registry type: %s", registryType)
	}

	return constructor(), nil
}

// GetSupportedTypes returns the list of supported registry types
func (f *DefaultFactory) GetSupportedTypes() []RegistryType {
	types := make([]RegistryType, 0, len(f.registries))
	for registryType := range f.registries {
		types = append(types, registryType)
	}
	return types
}

// CreateRegistryFromConfig is a convenience function that creates and configures a registry
func CreateRegistryFromConfig(registryType RegistryType, config RegistryConfig, authConfig AuthConfig) (ImageRegistry, error) {
	factory := NewDefaultFactory()

	registry, err := factory.CreateRegistry(registryType)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	// Validate configuration
	if err := registry.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid registry config: %w", err)
	}

	// NOTE: Authentication is handled individually by each registry client implementation

	return registry, nil
}
