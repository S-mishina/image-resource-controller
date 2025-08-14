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

// GitRepositoryConfig defines Git repository configuration for Resource Creation Controller
type GitRepositoryConfig struct {
	// URL of the Git repository
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// Branch to use (default: "main")
	// +kubebuilder:default="main"
	Branch string `json:"branch,omitempty"`

	// Path within the repository (default: "./")
	// +kubebuilder:default="./"
	Path string `json:"path,omitempty"`

	// SecretRef for Git authentication
	// +optional
	SecretRef *SecretRef `json:"secretRef,omitempty"`
}

// ValidationConfig defines template validation settings
type ValidationConfig struct {
	// DryRun enables dry-run validation before applying templates
	// +kubebuilder:default=true
	DryRun bool `json:"dryRun,omitempty"`
}

// FileTemplate defines a single file template for multi-file generation
type FileTemplate struct {
	// Name is a unique identifier for this file template
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// RelativePath is the path relative to gitRepository.path where this file will be created
	// Supports Go template variables like {{ .TagPrefix }}/deployments/{{ .ServiceName }}.yaml
	// +kubebuilder:validation:Required
	RelativePath string `json:"relativePath"`

	// Template is the Go template string for generating the file content
	// +kubebuilder:validation:Required
	Template string `json:"template"`
}

// ResourceTemplateSpec defines the desired state of ResourceTemplate
type ResourceTemplateSpec struct {
	// Template is the Go template string for generating Kubernetes resources
	// This field is used when multiFiles is not specified (legacy mode)
	// +optional
	Template string `json:"template,omitempty"`

	// MultiFiles enables multi-file generation with flexible directory structure
	// When specified, the legacy 'template' field is ignored
	// +optional
	MultiFiles []FileTemplate `json:"multiFiles,omitempty"`

	// Variables contains additional template variables (optional)
	// +optional
	Variables map[string]string `json:"variables,omitempty"`

	// GitRepository defines Git repository configuration for this template
	// +kubebuilder:validation:Required
	GitRepository GitRepositoryConfig `json:"gitRepository"`

	// Validation defines template validation settings
	// +optional
	Validation *ValidationConfig `json:"validation,omitempty"`
}

// ResourceTemplateStatus defines the observed state of ResourceTemplate
type ResourceTemplateStatus struct {
	// Conditions represent the latest available observations of an object's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastValidated is the last time the template was validated
	// +optional
	LastValidated *metav1.Time `json:"lastValidated,omitempty"`

	// ObservedGeneration is the last generation observed by the controller
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ResourceTemplate is the Schema for the resourcetemplates API
type ResourceTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceTemplateSpec   `json:"spec,omitempty"`
	Status ResourceTemplateStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ResourceTemplateList contains a list of ResourceTemplate
type ResourceTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResourceTemplate{}, &ResourceTemplateList{})
}
