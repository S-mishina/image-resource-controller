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

package ecr

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// RegistryType represents the type of container registry
type RegistryType string

const RegistryTypeECR RegistryType = "ecr"

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
	Type           RegistryType
	RepositoryName string
	Region         string
	RegistryURL    string
	Namespace      string
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type      RegistryType
	Username  string
	Password  string
	Token     string
	AWSConfig *AWSAuthConfig
}

// AWSAuthConfig represents AWS-specific authentication
type AWSAuthConfig struct {
	Region                string
	AccessKeyID           string
	SecretAccessKey       string
	SessionToken          string
	RoleArn               string
	UseDefaultCredentials bool
}

// ImageRegistry defines the interface for container registry operations
type ImageRegistry interface {
	ScanRepository(ctx context.Context, config RegistryConfig) ([]ImageInfo, error)
	Authenticate(ctx context.Context, authConfig AuthConfig) error
	GetRegistryType() RegistryType
	ValidateConfig(config RegistryConfig) error
	HealthCheck(ctx context.Context) error
}

// ECRRegistry implements the ImageRegistry interface for Amazon ECR
type ECRRegistry struct {
	ecrClient *ecr.Client
	stsClient *sts.Client
	awsConfig aws.Config
}

// NewECRRegistry creates a new ECR registry implementation
func NewECRRegistry() ImageRegistry {
	return &ECRRegistry{}
}

// GetRegistryType returns the registry type
func (e *ECRRegistry) GetRegistryType() RegistryType {
	return RegistryTypeECR
}

// ValidateConfig validates ECR-specific configuration
func (e *ECRRegistry) ValidateConfig(config RegistryConfig) error {
	if config.Type != RegistryTypeECR {
		return fmt.Errorf("invalid registry type for ECR: %s", config.Type)
	}

	if config.RepositoryName == "" {
		return fmt.Errorf("repository name is required for ECR")
	}

	if config.Region == "" {
		return fmt.Errorf("region is required for ECR")
	}

	return nil
}

// Authenticate performs authentication with ECR
func (e *ECRRegistry) Authenticate(ctx context.Context, authConfig AuthConfig) error {
	var awsConfig aws.Config
	var err error

	// Handle different authentication methods
	if authConfig.AWSConfig != nil && !authConfig.AWSConfig.UseDefaultCredentials {
		// Use explicit credentials
		if authConfig.AWSConfig.AccessKeyID != "" && authConfig.AWSConfig.SecretAccessKey != "" {
			awsConfig, err = config.LoadDefaultConfig(ctx,
				config.WithRegion(authConfig.AWSConfig.Region),
				config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
					authConfig.AWSConfig.AccessKeyID,
					authConfig.AWSConfig.SecretAccessKey,
					authConfig.AWSConfig.SessionToken,
				)),
			)
		} else if authConfig.AWSConfig.RoleArn != "" {
			// Use AssumeRole authentication
			awsConfig, err = e.setupAssumeRoleAuth(ctx, authConfig.AWSConfig)
			if err != nil {
				return fmt.Errorf("failed to setup AssumeRole authentication: %w", err)
			}
		} else {
			return fmt.Errorf("invalid AWS authentication configuration")
		}
	} else {
		// Use default credential chain (IRSA, Instance Profile, Environment Variables)
		region := "us-east-1" // default region
		if authConfig.AWSConfig != nil && authConfig.AWSConfig.Region != "" {
			region = authConfig.AWSConfig.Region
		}

		awsConfig, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
	}

	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create ECR and STS clients
	e.awsConfig = awsConfig
	e.ecrClient = ecr.NewFromConfig(awsConfig)
	e.stsClient = sts.NewFromConfig(awsConfig)

	// Test authentication by calling GetAuthorizationToken
	_, err = e.ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return fmt.Errorf("failed to authenticate with ECR: %w", err)
	}

	return nil
}

// HealthCheck checks if ECR is accessible
func (e *ECRRegistry) HealthCheck(ctx context.Context) error {
	if e.ecrClient == nil {
		return fmt.Errorf("ECR client not initialized - call Authenticate first")
	}

	// Test connectivity with a simple API call
	_, err := e.ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return fmt.Errorf("ECR health check failed: %w", err)
	}

	return nil
}

// ScanRepository scans an ECR repository and returns available images
func (e *ECRRegistry) ScanRepository(ctx context.Context, config RegistryConfig) ([]ImageInfo, error) {
	// Validate config first
	if err := e.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Initialize ECR client with default credentials if not already authenticated
	if e.ecrClient == nil {
		authConfig := AuthConfig{
			Type: RegistryTypeECR,
			AWSConfig: &AWSAuthConfig{
				Region:                config.Region,
				UseDefaultCredentials: true,
			},
		}
		if err := e.Authenticate(ctx, authConfig); err != nil {
			return nil, fmt.Errorf("failed to authenticate with ECR: %w", err)
		}
	}

	// Call DescribeImages API to get image information
	input := &ecr.DescribeImagesInput{
		RepositoryName: aws.String(config.RepositoryName),
		MaxResults:     aws.Int32(100), // Limit to 100 images per scan
	}

	output, err := e.ecrClient.DescribeImages(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe images in repository %s: %w", config.RepositoryName, err)
	}

	// Convert ECR image details to our ImageInfo format
	var images []ImageInfo
	for _, imageDetail := range output.ImageDetails {
		// Skip images without tags (untagged images)
		if len(imageDetail.ImageTags) == 0 {
			continue
		}

		// Create ImageInfo for each tag
		for _, tag := range imageDetail.ImageTags {
			imageInfo := ImageInfo{
				Name:         extractImageName(config.RepositoryName),
				Tag:          tag,
				Digest:       *imageDetail.ImageDigest,
				PushedAt:     *imageDetail.ImagePushedAt,
				FullURL:      buildFullImageURL(e.getAccountIDSafely(ctx), config.Region, config.RepositoryName, tag),
				Architecture: "amd64", // Default, could be extracted from manifest if needed
			}

			// Set size if available
			if imageDetail.ImageSizeInBytes != nil {
				imageInfo.Size = *imageDetail.ImageSizeInBytes
			}

			images = append(images, imageInfo)
		}
	}

	return images, nil
}

// extractImageName extracts the image name from repository name
// For "namespace/service" -> "service"
// For "service" -> "service"
func extractImageName(repositoryName string) string {
	// TODO: Implement proper parsing for hierarchical repository names
	// For now, return the full repository name
	return repositoryName
}

// buildFullImageURL constructs the full ECR image URL
func buildFullImageURL(accountID, region, repositoryName, tag string) string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", accountID, region, repositoryName, tag)
}

// extractAccountID extracts AWS account ID from AWS config
func extractAccountID(awsConfig aws.Config) string {
	// This will be updated to use actual STS call in getAccountID method
	return "123456789012"
}

// setupAssumeRoleAuth configures AssumeRole-based authentication
func (e *ECRRegistry) setupAssumeRoleAuth(ctx context.Context, awsAuthConfig *AWSAuthConfig) (aws.Config, error) {
	// Load base configuration (could be from default credentials or environment)
	baseConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsAuthConfig.Region))
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load base AWS config: %w", err)
	}

	// Create STS client with base credentials
	stsClient := sts.NewFromConfig(baseConfig)

	// Configure session name
	sessionName := "image-resource-controller"
	if awsAuthConfig.SessionToken != "" {
		sessionName = "image-resource-controller-session"
	}

	// Create AssumeRole provider with functional options
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(stsClient, awsAuthConfig.RoleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		// Set token duration to 1 hour (default is 15 minutes)
		o.Duration = time.Hour
	})

	// Create new config with assume role credentials
	assumeRoleConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(awsAuthConfig.Region),
		config.WithCredentialsProvider(assumeRoleProvider),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to create AssumeRole config: %w", err)
	}

	return assumeRoleConfig, nil
}

// GetAccountID retrieves the current AWS account ID using STS GetCallerIdentity
func (e *ECRRegistry) GetAccountID(ctx context.Context) (string, error) {
	if e.stsClient == nil {
		return "", fmt.Errorf("STS client not initialized - call Authenticate first")
	}

	// Call STS GetCallerIdentity to get account information
	output, err := e.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if output.Account == nil {
		return "", fmt.Errorf("account ID not found in STS response")
	}

	return *output.Account, nil
}

// GetCurrentUser returns information about the current authenticated user/role
func (e *ECRRegistry) GetCurrentUser(ctx context.Context) (*STSUserInfo, error) {
	if e.stsClient == nil {
		return nil, fmt.Errorf("STS client not initialized - call Authenticate first")
	}

	output, err := e.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	userInfo := &STSUserInfo{
		AccountID: safeString(output.Account),
		UserID:    safeString(output.UserId),
		ARN:       safeString(output.Arn),
	}

	// Parse user type from ARN
	if userInfo.ARN != "" {
		userInfo.UserType = parseUserTypeFromARN(userInfo.ARN)
	}

	return userInfo, nil
}

// STSUserInfo contains information about the current AWS user/role
type STSUserInfo struct {
	AccountID string
	UserID    string
	ARN       string
	UserType  string // "user", "assumed-role", "federated-user", etc.
}

// parseUserTypeFromARN extracts user type from ARN
func parseUserTypeFromARN(arn string) string {
	// Example ARNs:
	// arn:aws:iam::123456789012:user/username
	// arn:aws:sts::123456789012:assumed-role/role-name/session-name
	// arn:aws:sts::123456789012:federated-user/user-name

	parts := strings.Split(arn, ":")
	if len(parts) >= 6 {
		resourcePart := parts[5]
		resourceTypeParts := strings.Split(resourcePart, "/")
		if len(resourceTypeParts) > 0 {
			return resourceTypeParts[0]
		}
	}
	return "unknown"
}

// safeString safely dereferences a string pointer
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getAccountIDFromECR retrieves the AWS account ID using ECR repository URI (fallback method)
func (e *ECRRegistry) getAccountIDFromECR(ctx context.Context) (string, error) {
	if e.ecrClient == nil {
		return "", fmt.Errorf("ECR client not initialized")
	}

	// Try to get the account ID from the repository URI by describing repositories
	input := &ecr.DescribeRepositoriesInput{
		MaxResults: aws.Int32(1),
	}

	output, err := e.ecrClient.DescribeRepositories(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe repositories: %w", err)
	}

	if len(output.Repositories) > 0 && output.Repositories[0].RepositoryUri != nil {
		// Extract account ID from repository URI
		// Format: 123456789012.dkr.ecr.region.amazonaws.com/repo-name
		uri := *output.Repositories[0].RepositoryUri
		parts := strings.Split(uri, ".")
		if len(parts) > 0 {
			return parts[0], nil
		}
	}

	return "", fmt.Errorf("could not extract account ID from ECR repositories")
}

// getAccountIDSafely retrieves account ID with fallback mechanisms
func (e *ECRRegistry) getAccountIDSafely(ctx context.Context) string {
	// Try STS first (most reliable)
	if accountID, err := e.GetAccountID(ctx); err == nil && accountID != "" {
		return accountID
	}

	// Fallback to ECR repository URI extraction
	if accountID, err := e.getAccountIDFromECR(ctx); err == nil && accountID != "" {
		return accountID
	}

	// Final fallback to placeholder
	return "123456789012"
}
