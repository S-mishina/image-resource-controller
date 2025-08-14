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

package v1beta1

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ECRRepository defines ECR repository configuration
type ECRRepository struct {
	// Region is the AWS region (e.g., "us-east-1")
	// +kubebuilder:validation:Required
	Region string `json:"region"`

	// RepositoryPattern for pattern-based repository matching (e.g., "team-a/*", "my-service")
	// Exactly one of RepositoryPattern, ImageNamePattern, or ImagePattern must be specified
	// +optional
	RepositoryPattern string `json:"repositoryPattern,omitempty"`

	// ImageNamePattern for image name-based matching across all repositories (e.g., "nginx-base", "*-service")
	// Exactly one of RepositoryPattern, ImageNamePattern, or ImagePattern must be specified
	// +optional
	ImageNamePattern string `json:"imageNamePattern,omitempty"`

	// ImagePattern for combined repository and image pattern matching (e.g., "team-a/*:v*", "*/nginx:stable-*")
	// Exactly one of RepositoryPattern, ImageNamePattern, or ImagePattern must be specified
	// +optional
	ImagePattern string `json:"imagePattern,omitempty"`

	// MaxRepositories limits the maximum number of repositories to scan (default: 50)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=200
	// +kubebuilder:default=50
	MaxRepositories int32 `json:"maxRepositories,omitempty"`

	// MaxConcurrentScans limits the number of concurrent repository scans (default: 10)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:default=10
	MaxConcurrentScans int32 `json:"maxConcurrentScans,omitempty"`

	// ScanTimeout specifies the timeout for the entire scan operation (default: "5m")
	// +kubebuilder:default="5m"
	ScanTimeout string `json:"scanTimeout,omitempty"`
}

// PolicySpec defines the image selection policy
type PolicySpec struct {
	// PerRepository enables per-repository policy application instead of cross-repository policy
	// When true, policy is applied to each repository separately, creating ImageDetected per repository
	// When false (default), policy is applied across all repositories, typically creating fewer ImageDetected resources
	// +kubebuilder:default=false
	PerRepository bool `json:"perRepository,omitempty"`

	// Semver policy for selecting images by semantic version
	// +optional
	Semver *SemverPolicy `json:"semver,omitempty"`

	// Alphabetical policy for selecting images by alphabetical order
	// +optional
	Alphabetical *AlphabeticalPolicy `json:"alphabetical,omitempty"`

	// Pattern policy for selecting images by regular expression
	// +optional
	Pattern *PatternPolicy `json:"pattern,omitempty"`
}

// SemverPolicy defines semantic version-based selection
type SemverPolicy struct {
	// Range specifies the semver range (e.g., ">=1.0.0")
	// +kubebuilder:validation:Required
	Range string `json:"range"`
}

// AlphabeticalPolicy defines alphabetical order-based selection
type AlphabeticalPolicy struct {
	// Order specifies the sorting order ("asc" or "desc")
	// +kubebuilder:validation:Enum=asc;desc
	// +kubebuilder:default="asc"
	Order string `json:"order,omitempty"`
}

// PatternPolicy defines regex pattern-based selection
type PatternPolicy struct {
	// Regex specifies the regular expression pattern
	// +kubebuilder:validation:Required
	Regex string `json:"regex"`

	// ExtractPrefix enables tag prefix extraction from regex capture groups
	// When true, the first capture group in the regex will be extracted as tag prefix
	// +kubebuilder:default=false
	// +optional
	ExtractPrefix bool `json:"extractPrefix,omitempty"`
}

// SecretRef defines a reference to a Secret resource
type SecretRef struct {
	// Name of the Secret resource
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// AWSAuthConfig defines AWS authentication configuration
type AWSAuthConfig struct {
	// SecretRef for AWS credentials (optional)
	// +optional
	SecretRef *SecretRef `json:"secretRef,omitempty"`

	// RoleArn for IAM role-based authentication (optional)
	// +optional
	RoleArn string `json:"roleArn,omitempty"`
}

// TemplateRef defines a reference to a ResourceTemplate
type TemplateRef struct {
	// Name of the ResourceTemplate
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the ResourceTemplate (optional, defaults to same namespace)
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// ImageResourcePolicySpec defines the desired state of ImageResourcePolicy
type ImageResourcePolicySpec struct {
	// ECRRepository defines the ECR repository to monitor
	// +kubebuilder:validation:Required
	ECRRepository ECRRepository `json:"ecrRepository"`

	// Policy defines the image selection criteria
	// +kubebuilder:validation:Required
	Policy PolicySpec `json:"policy"`

	// TemplateRef references the ResourceTemplate to use for resource creation
	// +kubebuilder:validation:Required
	TemplateRef TemplateRef `json:"templateRef"`

	// AWS defines AWS authentication configuration (optional)
	// +optional
	AWS *AWSAuthConfig `json:"aws,omitempty"`

	// Suspend stops the controller from processing this policy
	// +kubebuilder:default=false
	Suspend bool `json:"suspend,omitempty"`

	// TTLDays specifies the number of days after which generated ImageDetected resources will be cleaned up
	// Default is 7 days. Set to 0 to disable automatic cleanup.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=365
	// +kubebuilder:default=7
	TTLDays int32 `json:"ttlDays,omitempty"`
}

// ImageResourcePolicyStatus defines the observed state of ImageResourcePolicy
type ImageResourcePolicyStatus struct {
	// Conditions represent the latest available observations of an object's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastScannedTime is the last time the ECR repository was scanned
	// +optional
	LastScannedTime *metav1.Time `json:"lastScannedTime,omitempty"`

	// ObservedGeneration is the last generation observed by the controller
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ImageResourcePolicy is the Schema for the imageresourcepolicies API
type ImageResourcePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageResourcePolicySpec   `json:"spec,omitempty"`
	Status ImageResourcePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageResourcePolicyList contains a list of ImageResourcePolicy
type ImageResourcePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageResourcePolicy `json:"items"`
}

// Validate validates the ECRRepository configuration
func (e *ECRRepository) Validate() error {
	patterns := []string{e.RepositoryPattern, e.ImageNamePattern, e.ImagePattern}

	nonEmpty := 0
	for _, p := range patterns {
		if p != "" {
			nonEmpty++
		}
	}

	if nonEmpty != 1 {
		return fmt.Errorf("exactly one pattern type must be specified (repositoryPattern, imageNamePattern, or imagePattern)")
	}

	// Validate pattern syntax
	if e.RepositoryPattern != "" {
		if err := validateRepositoryPattern(e.RepositoryPattern); err != nil {
			return fmt.Errorf("invalid repositoryPattern: %w", err)
		}
	}

	return nil
}

// validateRepositoryPattern validates repository pattern syntax
func validateRepositoryPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	// Prevent dangerous patterns
	if pattern == "*" {
		return fmt.Errorf("wildcard-only pattern '*' is not allowed for performance reasons")
	}

	// Basic pattern validation - could be enhanced with more sophisticated checks
	if strings.Contains(pattern, "**") {
		return fmt.Errorf("double wildcard '**' is not supported")
	}

	return nil
}

// GetPatternType returns the type of pattern being used
func (e *ECRRepository) GetPatternType() string {
	if e.RepositoryPattern != "" {
		return "repository"
	}
	if e.ImageNamePattern != "" {
		return "imageName"
	}
	if e.ImagePattern != "" {
		return "image"
	}
	return "none"
}

// GetPattern returns the active pattern value
func (e *ECRRepository) GetPattern() string {
	if e.RepositoryPattern != "" {
		return e.RepositoryPattern
	}
	if e.ImageNamePattern != "" {
		return e.ImageNamePattern
	}
	if e.ImagePattern != "" {
		return e.ImagePattern
	}
	return ""
}

func init() {
	SchemeBuilder.Register(&ImageResourcePolicy{}, &ImageResourcePolicyList{})
}
