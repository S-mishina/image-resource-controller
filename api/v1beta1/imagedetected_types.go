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

// SourcePolicyRef defines a reference to the source ImageResourcePolicy
type SourcePolicyRef struct {
	// Name of the source ImageResourcePolicy
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the source ImageResourcePolicy
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// ImageDetectedSpec defines the desired state of ImageDetected
type ImageDetectedSpec struct {
	// ImageName is the base name of the image (e.g., "web-app")
	// +kubebuilder:validation:Required
	ImageName string `json:"imageName"`

	// ImageTag is the tag of the detected image (e.g., "v1.2.3")
	// +kubebuilder:validation:Required
	ImageTag string `json:"imageTag"`

	// ImageDigest is the digest of the detected image
	// +kubebuilder:validation:Required
	ImageDigest string `json:"imageDigest"`

	// FullImageName is the complete ECR image URL
	// +kubebuilder:validation:Required
	FullImageName string `json:"fullImageName"`

	// TagPrefix is the extracted prefix from the image tag when extractPrefix is enabled
	// This is used for prefix-aware duplicate detection and version management
	// +optional
	TagPrefix string `json:"tagPrefix,omitempty"`

	// SourcePolicy references the ImageResourcePolicy that detected this image
	// +kubebuilder:validation:Required
	SourcePolicy SourcePolicyRef `json:"sourcePolicy"`

	// DetectedAt is the time when this image was detected
	// +kubebuilder:validation:Required
	DetectedAt metav1.Time `json:"detectedAt"`
}

// ImageDetectedStatus defines the observed state of ImageDetected
type ImageDetectedStatus struct {
	// Conditions represent the latest available observations of an object's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Phase represents the current phase of the ImageDetected lifecycle
	// +kubebuilder:validation:Enum=Pending;Processing;Completed;Failed
	// +kubebuilder:default="Pending"
	Phase string `json:"phase,omitempty"`

	// ResourceCreated indicates whether the resource has been created by Resource Creation Controller
	// +kubebuilder:default=false
	ResourceCreated bool `json:"resourceCreated,omitempty"`

	// GitCommitSHA is the SHA of the Git commit created by Resource Creation Controller
	// +optional
	GitCommitSHA string `json:"gitCommitSHA,omitempty"`

	// ProcessedAt is the time when the resource creation was completed
	// +optional
	ProcessedAt *metav1.Time `json:"processedAt,omitempty"`

	// ObservedGeneration is the last generation observed by the controller
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ImageDetected is the Schema for the imagedetecteds API
type ImageDetected struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageDetectedSpec   `json:"spec,omitempty"`
	Status ImageDetectedStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageDetectedList contains a list of ImageDetected
type ImageDetectedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageDetected `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageDetected{}, &ImageDetectedList{})
}
