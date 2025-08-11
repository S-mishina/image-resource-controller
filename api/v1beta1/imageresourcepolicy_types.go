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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ECRRepository defines ECR repository configuration
type ECRRepository struct {
	// RepositoryName is the ECR repository name (e.g., "my-service" or "namespace/my-service")
	// +kubebuilder:validation:Required
	RepositoryName string `json:"repositoryName"`

	// Region is the AWS region (e.g., "us-east-1")
	// +kubebuilder:validation:Required
	Region string `json:"region"`
}

// PolicySpec defines the image selection policy
type PolicySpec struct {
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

// ImageResourcePolicySpec defines the desired state of ImageResourcePolicy
type ImageResourcePolicySpec struct {
	// ECRRepository defines the ECR repository to monitor
	// +kubebuilder:validation:Required
	ECRRepository ECRRepository `json:"ecrRepository"`

	// Policy defines the image selection criteria
	// +kubebuilder:validation:Required
	Policy PolicySpec `json:"policy"`

	// AWS defines AWS authentication configuration (optional)
	// +optional
	AWS *AWSAuthConfig `json:"aws,omitempty"`

	// Suspend stops the controller from processing this policy
	// +kubebuilder:default=false
	Suspend bool `json:"suspend,omitempty"`
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

func init() {
	SchemeBuilder.Register(&ImageResourcePolicy{}, &ImageResourcePolicyList{})
}
