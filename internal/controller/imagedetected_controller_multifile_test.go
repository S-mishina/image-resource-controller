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

package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	automationv1beta1 "github.com/S-mishina/image-resource-controller/api/v1beta1"
	"github.com/S-mishina/image-resource-controller/internal/template"
)

func TestImageDetectedReconciler_processMultiFileTemplate(t *testing.T) {
	reconciler := &ImageDetectedReconciler{
		TemplateProcessor: template.NewProcessor(),
	}

	tests := []struct {
		name              string
		resourceTemplate  *automationv1beta1.ResourceTemplate
		vars              template.TemplateVars
		expectedManifests map[string]string
		expectError       bool
		expectedFileCount int
	}{
		{
			name: "Multi-file template with tag prefix",
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					MultiFiles: []automationv1beta1.FileTemplate{
						{
							Name:         "deployment",
							RelativePath: "{{ .TagPrefix }}/deployments/{{ .ServiceName }}.yaml",
							Template: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .ServiceName }}
  labels:
    app: {{ .ServiceName }}
    environment: {{ .TagPrefix }}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: {{ .ServiceName }}
  template:
    metadata:
      labels:
        app: {{ .ServiceName }}
    spec:
      containers:
      - name: {{ .ServiceName }}
        image: {{ .FullImageName }}`,
						},
						{
							Name:         "service",
							RelativePath: "{{ .TagPrefix }}/services/{{ .ServiceName }}.yaml",
							Template: `apiVersion: v1
kind: Service
metadata:
  name: {{ .ServiceName }}
  labels:
    app: {{ .ServiceName }}
    environment: {{ .TagPrefix }}
spec:
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: {{ .ServiceName }}`,
						},
					},
					GitRepository: automationv1beta1.GitRepositoryConfig{
						Path: "./applications",
					},
				},
			},
			vars: template.TemplateVars{
				ServiceName:   "webapp",
				TagPrefix:     "dev",
				FullImageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/webapp:dev-v1.0.0",
			},
			expectedFileCount: 2,
			expectError:       false,
		},
		{
			name: "Multi-file template with shared config",
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					MultiFiles: []automationv1beta1.FileTemplate{
						{
							Name:         "deployment",
							RelativePath: "{{ .TagPrefix | default \"default\" }}/deployments/{{ .ServiceName }}.yaml",
							Template: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .ServiceName }}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {{ .ServiceName }}
  template:
    spec:
      containers:
      - name: {{ .ServiceName }}
        image: {{ .FullImageName }}`,
						},
						{
							Name:         "configmap",
							RelativePath: "shared/configs/{{ .ServiceName }}-config.yaml",
							Template: `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .ServiceName }}-config
data:
  environment: "{{ .TagPrefix | default "default" }}"
  image.tag: "{{ .ImageTag }}"`,
						},
					},
					GitRepository: automationv1beta1.GitRepositoryConfig{
						Path: "./applications",
					},
				},
			},
			vars: template.TemplateVars{
				ServiceName:   "api",
				TagPrefix:     "staging",
				ImageTag:      "v2.1.0",
				FullImageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/api:staging-v2.1.0",
			},
			expectedFileCount: 2,
			expectError:       false,
		},
		{
			name: "Multi-file template with empty prefix (default)",
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					MultiFiles: []automationv1beta1.FileTemplate{
						{
							Name:         "deployment",
							RelativePath: "{{ .TagPrefix | default \"default\" }}/deployments/{{ .ServiceName }}.yaml",
							Template: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .ServiceName }}
spec:
  replicas: 1`,
						},
					},
					GitRepository: automationv1beta1.GitRepositoryConfig{
						Path: "./applications",
					},
				},
			},
			vars: template.TemplateVars{
				ServiceName:   "worker",
				TagPrefix:     "", // empty prefix
				FullImageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker:v1.0.0",
			},
			expectedFileCount: 1,
			expectError:       false,
		},
		{
			name: "Multi-file template with invalid template syntax",
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					MultiFiles: []automationv1beta1.FileTemplate{
						{
							Name:         "invalid",
							RelativePath: "{{ .TagPrefix }}/deployments/{{ .ServiceName }}.yaml",
							Template:     "metadata:\n  name: {{ .InvalidSyntax", // Invalid template
						},
					},
					GitRepository: automationv1beta1.GitRepositoryConfig{
						Path: "./applications",
					},
				},
			},
			vars: template.TemplateVars{
				ServiceName: "test",
				TagPrefix:   "dev",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			manifests, err := reconciler.processMultiFileTemplate(ctx, tt.resourceTemplate, tt.vars)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedFileCount, len(manifests))

			// Validate path construction
			for path, content := range manifests {
				assert.NotEmpty(t, content)
				assert.Contains(t, path, "./applications/")

				// Check that content is valid YAML-like (basic validation)
				assert.Contains(t, content, "apiVersion:")
				assert.Contains(t, content, "kind:")
				assert.Contains(t, content, "metadata:")
			}

			// Specific validations for the first test case
			if tt.name == "Multi-file template with tag prefix" {
				deploymentPath := "./applications/dev/deployments/webapp.yaml"
				servicePath := "./applications/dev/services/webapp.yaml"

				assert.Contains(t, manifests, deploymentPath)
				assert.Contains(t, manifests, servicePath)

				deploymentContent := manifests[deploymentPath]
				assert.Contains(t, deploymentContent, "name: webapp")
				assert.Contains(t, deploymentContent, "environment: dev")

				serviceContent := manifests[servicePath]
				assert.Contains(t, serviceContent, "name: webapp")
				assert.Contains(t, serviceContent, "environment: dev")
			}

			// Specific validations for the shared config test case
			if tt.name == "Multi-file template with shared config" {
				deploymentPath := "./applications/staging/deployments/api.yaml"
				configPath := "./applications/shared/configs/api-config.yaml"

				assert.Contains(t, manifests, deploymentPath)
				assert.Contains(t, manifests, configPath)

				configContent := manifests[configPath]
				assert.Contains(t, configContent, "environment: \"staging\"")
				assert.Contains(t, configContent, "image.tag: \"v2.1.0\"")
			}

			// Specific validations for empty prefix test case
			if tt.name == "Multi-file template with empty prefix (default)" {
				deploymentPath := "./applications/default/deployments/worker.yaml"
				assert.Contains(t, manifests, deploymentPath)
			}
		})
	}
}

func TestImageDetectedReconciler_processSingleFileTemplate(t *testing.T) {
	reconciler := &ImageDetectedReconciler{
		TemplateProcessor: template.NewProcessor(),
	}

	tests := []struct {
		name             string
		imageDetected    *automationv1beta1.ImageDetected
		resourceTemplate *automationv1beta1.ResourceTemplate
		vars             template.TemplateVars
		expectedFileName string
		expectError      bool
	}{
		{
			name: "Single file template with tag prefix",
			imageDetected: &automationv1beta1.ImageDetected{
				Spec: automationv1beta1.ImageDetectedSpec{
					ImageName: "webapp",
					TagPrefix: "dev",
				},
			},
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					Template: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .ServiceName }}
spec:
  replicas: 1`,
				},
			},
			vars: template.TemplateVars{
				ServiceName: "webapp",
				TagPrefix:   "dev",
			},
			expectedFileName: "webapp-dev.yaml",
			expectError:      false,
		},
		{
			name: "Single file template without tag prefix",
			imageDetected: &automationv1beta1.ImageDetected{
				Spec: automationv1beta1.ImageDetectedSpec{
					ImageName: "api",
					TagPrefix: "",
				},
			},
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					Template: `apiVersion: v1
kind: Service
metadata:
  name: {{ .ServiceName }}`,
				},
			},
			vars: template.TemplateVars{
				ServiceName: "api",
				TagPrefix:   "",
			},
			expectedFileName: "api.yaml",
			expectError:      false,
		},
		{
			name: "Single file template with empty template field",
			imageDetected: &automationv1beta1.ImageDetected{
				Spec: automationv1beta1.ImageDetectedSpec{
					ImageName: "test",
				},
			},
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					Template: "", // Empty template should cause error
				},
			},
			vars: template.TemplateVars{
				ServiceName: "test",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			manifests, err := reconciler.processSingleFileTemplate(ctx, tt.imageDetected, tt.resourceTemplate, tt.vars)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, 1, len(manifests))

			// Check expected filename
			assert.Contains(t, manifests, tt.expectedFileName)

			content := manifests[tt.expectedFileName]
			assert.NotEmpty(t, content)
			assert.Contains(t, content, "apiVersion:")
			assert.Contains(t, content, "kind:")
			assert.Contains(t, content, "metadata:")
		})
	}
}

func TestImageDetectedReconciler_processTemplate_Decision(t *testing.T) {
	reconciler := &ImageDetectedReconciler{
		TemplateProcessor: template.NewProcessor(),
	}

	imageDetected := &automationv1beta1.ImageDetected{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-image",
			Namespace: "default",
		},
		Spec: automationv1beta1.ImageDetectedSpec{
			ImageName:     "webapp",
			ImageTag:      "dev-v1.0.0",
			TagPrefix:     "dev",
			FullImageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/webapp:dev-v1.0.0",
		},
	}

	tests := []struct {
		name              string
		resourceTemplate  *automationv1beta1.ResourceTemplate
		expectedFileCount int
		expectMultiFile   bool
	}{
		{
			name: "Should use multi-file template when multiFiles is specified",
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					Template: `legacy template`, // This should be ignored
					MultiFiles: []automationv1beta1.FileTemplate{
						{
							Name:         "deployment",
							RelativePath: "{{ .TagPrefix }}/deployments/{{ .ServiceName }}.yaml",
							Template:     "apiVersion: apps/v1\nkind: Deployment",
						},
						{
							Name:         "service",
							RelativePath: "{{ .TagPrefix }}/services/{{ .ServiceName }}.yaml",
							Template:     "apiVersion: v1\nkind: Service",
						},
					},
					GitRepository: automationv1beta1.GitRepositoryConfig{
						Path: "./applications",
					},
				},
			},
			expectedFileCount: 2,
			expectMultiFile:   true,
		},
		{
			name: "Should use single-file template when multiFiles is empty",
			resourceTemplate: &automationv1beta1.ResourceTemplate{
				Spec: automationv1beta1.ResourceTemplateSpec{
					Template: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .ServiceName }}`,
					MultiFiles: nil, // No multi-files specified
					GitRepository: automationv1beta1.GitRepositoryConfig{
						Path: "./applications",
					},
				},
			},
			expectedFileCount: 1,
			expectMultiFile:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			manifests, err := reconciler.processTemplate(ctx, imageDetected, tt.resourceTemplate)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedFileCount, len(manifests))

			if tt.expectMultiFile {
				// Multi-file templates should have path prefixes
				for path := range manifests {
					assert.Contains(t, path, "./applications/")
					assert.Contains(t, path, "dev/") // Tag prefix in path
				}
			} else {
				// Single-file template should have simple filename
				for fileName := range manifests {
					assert.Equal(t, "webapp-dev.yaml", fileName)
				}
			}
		})
	}
}
