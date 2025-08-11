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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ImageDetectedSpec defines the desired state of ImageDetected
type ImageDetectedSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of ImageDetected. Edit imagedetected_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// ImageDetectedStatus defines the observed state of ImageDetected
type ImageDetectedStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
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
