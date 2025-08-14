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

package template

import (
	"strings"
	"testing"
)

func TestBuildTemplateVars(t *testing.T) {
	processor := NewProcessor()

	tests := []struct {
		name           string
		fullImageName  string
		imageTag       string
		imageDigest    string
		additionalVars map[string]string
		expectedVars   TemplateVars
		expectError    bool
	}{
		{
			name:           "Simple ECR image",
			fullImageName:  "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3",
			imageTag:       "v1.2.3",
			imageDigest:    "sha256:abc123",
			additionalVars: map[string]string{"env": "production"},
			expectedVars: TemplateVars{
				ImageTag:          "v1.2.3",
				ImageDigest:       "sha256:abc123",
				FullImageName:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3",
				RepositoryName:    "my-service",
				Registry:          "123456789012.dkr.ecr.us-east-1.amazonaws.com",
				Region:            "us-east-1",
				AccountID:         "123456789012",
				Namespace:         "",
				ServiceName:       "my-service",
				K8sCompatibleName: "my-service",
				Variables:         map[string]string{"env": "production"},
			},
			expectError: false,
		},
		{
			name:          "Hierarchical ECR image",
			fullImageName: "123456789012.dkr.ecr.us-west-2.amazonaws.com/team-a/user-service:v2.0.0",
			imageTag:      "v2.0.0",
			imageDigest:   "sha256:def456",
			expectedVars: TemplateVars{
				ImageTag:          "v2.0.0",
				ImageDigest:       "sha256:def456",
				FullImageName:     "123456789012.dkr.ecr.us-west-2.amazonaws.com/team-a/user-service:v2.0.0",
				RepositoryName:    "team-a/user-service",
				Registry:          "123456789012.dkr.ecr.us-west-2.amazonaws.com",
				Region:            "us-west-2",
				AccountID:         "123456789012",
				Namespace:         "team-a",
				ServiceName:       "user-service",
				K8sCompatibleName: "team-a-user-service",
				Variables:         nil,
			},
			expectError: false,
		},
		{
			name:          "Invalid ECR URL",
			fullImageName: "invalid-url:latest",
			imageTag:      "latest",
			imageDigest:   "sha256:abc123",
			expectError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vars, err := processor.BuildTemplateVars(test.fullImageName, test.imageTag, test.imageDigest, test.additionalVars)

			if test.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify key fields
			if vars.ImageTag != test.expectedVars.ImageTag {
				t.Errorf("ImageTag: expected %s, got %s", test.expectedVars.ImageTag, vars.ImageTag)
			}
			if vars.ServiceName != test.expectedVars.ServiceName {
				t.Errorf("ServiceName: expected %s, got %s", test.expectedVars.ServiceName, vars.ServiceName)
			}
			if vars.Namespace != test.expectedVars.Namespace {
				t.Errorf("Namespace: expected %s, got %s", test.expectedVars.Namespace, vars.Namespace)
			}
			if vars.K8sCompatibleName != test.expectedVars.K8sCompatibleName {
				t.Errorf("K8sCompatibleName: expected %s, got %s", test.expectedVars.K8sCompatibleName, vars.K8sCompatibleName)
			}
		})
	}
}

func TestProcessTemplate(t *testing.T) {
	processor := NewProcessor()

	vars := TemplateVars{
		ImageTag:          "v1.2.3",
		ImageDigest:       "sha256:abc123",
		FullImageName:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3",
		RepositoryName:    "my-service",
		Registry:          "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		Region:            "us-east-1",
		AccountID:         "123456789012",
		ServiceName:       "my-service",
		K8sCompatibleName: "my-service",
		Variables:         map[string]string{"replicas": "3"},
	}

	tests := []struct {
		name            string
		template        string
		expectError     bool
		expectedContent []string
	}{
		{
			name: "Basic Deployment template",
			template: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .ServiceName }}
  labels:
    app: {{ .ServiceName }}
spec:
  replicas: {{ .Variables.replicas }}
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
        image: {{ .FullImageName }}:{{ .ImageTag }}`,
			expectError: false,
			expectedContent: []string{
				"name: my-service",
				"replicas: 3",
				"image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3:v1.2.3",
			},
		},
		{
			name: "Template with custom functions",
			template: `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .ServiceName | toLower }}
  labels:
    service: {{ .ServiceName | k8sName }}
data:
  region: {{ .Region | toUpper }}
  account: {{ .AccountID }}`,
			expectError: false,
			expectedContent: []string{
				"name: my-service",
				"service: my-service",
				"region: US-EAST-1",
				"account: 123456789012",
			},
		},
		{
			name: "Multi-document YAML",
			template: `apiVersion: v1
kind: Service
metadata:
  name: {{ .ServiceName }}
spec:
  selector:
    app: {{ .ServiceName }}
  ports:
  - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .ServiceName }}
spec:
  selector:
    matchLabels:
      app: {{ .ServiceName }}`,
			expectError: false,
			expectedContent: []string{
				"kind: Service",
				"kind: Deployment",
				"name: my-service",
			},
		},
		{
			name: "Invalid template syntax",
			template: `metadata:
  name: {{ .ServiceName
spec:
  invalid: {{ .NonExistentField }}`,
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := processor.ProcessTemplate(test.template, vars)

			if test.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			resultStr := string(result)
			for _, expected := range test.expectedContent {
				if !strings.Contains(resultStr, expected) {
					t.Errorf("Expected content '%s' not found in result:\n%s", expected, resultStr)
				}
			}
		})
	}
}

func TestSanitizeForK8s(t *testing.T) {
	processor := NewProcessor()

	tests := []struct {
		input    string
		expected string
	}{
		{"my-service", "my-service"},
		{"MyService", "myservice"},
		{"my_service", "my-service"},
		{"my.service", "my-service"},
		{"team-a/user-service", "team-a-user-service"},
		{"Service123", "service123"},
		{"", "unnamed"},
		{"service-", "service"},
		{"-service", "service"},
		{"very-long-service-name-that-exceeds-kubernetes-dns-label-limit-of-63-characters", "very-long-service-name-that-exceeds-kubernetes-dns-label-limit"},
	}

	for _, test := range tests {
		result := processor.sanitizeForK8s(test.input)
		if result != test.expected {
			t.Errorf("sanitizeForK8s(%s) = %s, expected %s", test.input, result, test.expected)
		}

		// Verify result is valid DNS-1123 label
		if result != "" && len(result) <= 63 {
			if !isValidK8sName(result) {
				t.Errorf("sanitizeForK8s(%s) produced invalid K8s name: %s", test.input, result)
			}
		}
	}
}

func TestValidateTemplate(t *testing.T) {
	processor := NewProcessor()

	tests := []struct {
		name        string
		template    string
		expectError bool
	}{
		{
			name: "Valid template",
			template: `apiVersion: v1
kind: Pod
metadata:
  name: {{ .ServiceName }}`,
			expectError: false,
		},
		{
			name: "Invalid template - unclosed action",
			template: `metadata:
  name: {{ .ServiceName`,
			expectError: true,
		},
		{
			name: "Valid template with functions",
			template: `metadata:
  name: {{ .ServiceName | toLower }}`,
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := processor.ValidateTemplate(test.template)
			if test.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestAnalyzeTemplate(t *testing.T) {
	processor := NewProcessor()
	vars := TemplateVars{
		ServiceName: "test-service",
		ImageTag:    "v1.0.0",
	}

	tests := []struct {
		name             string
		template         string
		expectedUsedVars []string
	}{
		{
			name: "Simple template",
			template: `metadata:
  name: {{ .ServiceName }}
spec:
  image: service:{{ .ImageTag }}`,
			expectedUsedVars: []string{"ServiceName", "ImageTag"},
		},
		{
			name: "Template with Variables",
			template: `spec:
  replicas: {{ .Variables.replicas }}`,
			expectedUsedVars: []string{"Variables"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := processor.AnalyzeTemplate(test.template, vars)

			if !result.Valid {
				t.Errorf("Template should be valid, but got errors: %v", result.Errors)
			}

			for _, expectedVar := range test.expectedUsedVars {
				found := false
				for _, usedVar := range result.UsedVars {
					if usedVar == expectedVar {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected variable '%s' to be in used vars, but got: %v", expectedVar, result.UsedVars)
				}
			}
		})
	}
}

func TestSplitYAMLDocuments(t *testing.T) {
	processor := NewProcessor()

	multiDocYAML := `apiVersion: v1
kind: Service
metadata:
  name: my-service
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config`

	documents := processor.SplitYAMLDocuments([]byte(multiDocYAML))

	expectedDocs := 3
	if len(documents) != expectedDocs {
		t.Errorf("Expected %d documents, got %d", expectedDocs, len(documents))
	}

	// Check first document contains Service
	if len(documents) > 0 && !strings.Contains(string(documents[0]), "kind: Service") {
		t.Error("First document should contain Service")
	}

	// Check second document contains Deployment
	if len(documents) > 1 && !strings.Contains(string(documents[1]), "kind: Deployment") {
		t.Error("Second document should contain Deployment")
	}

	// Check third document contains ConfigMap
	if len(documents) > 2 && !strings.Contains(string(documents[2]), "kind: ConfigMap") {
		t.Error("Third document should contain ConfigMap")
	}
}

func TestCustomTemplateFunctions(t *testing.T) {
	processor := NewProcessor()

	vars := TemplateVars{
		ServiceName: "My-Service",
		Region:      "us-east-1",
		Variables:   map[string]string{"env": "prod"},
	}

	tests := []struct {
		name     string
		template string
		expected string
	}{
		{
			name:     "toLower function",
			template: `{{ .ServiceName | toLower }}`,
			expected: "my-service",
		},
		{
			name:     "toUpper function",
			template: `{{ .Region | toUpper }}`,
			expected: "US-EAST-1",
		},
		{
			name:     "default function",
			template: `{{ .Variables.missing | default "default-value" }}`,
			expected: "default-value",
		},
		{
			name:     "ternary function",
			template: `{{ ternary "prod" "dev" true }}`,
			expected: "prod",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := processor.ProcessTemplate(test.template, vars)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			resultStr := strings.TrimSpace(string(result))
			if resultStr != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, resultStr)
			}
		})
	}
}

// Helper function to validate K8s DNS-1123 label compliance
func isValidK8sName(name string) bool {
	if len(name) > 63 || len(name) == 0 {
		return false
	}

	for i, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
		if (i == 0 || i == len(name)-1) && r == '-' {
			return false
		}
	}
	return true
}

func TestProcessor_ProcessTemplateString(t *testing.T) {
	processor := NewProcessor()

	tests := []struct {
		name     string
		template string
		vars     TemplateVars
		expected string
		wantErr  bool
	}{
		{
			name:     "simple string template",
			template: "Hello {{ .ServiceName }}!",
			vars: TemplateVars{
				ServiceName: "webapp",
			},
			expected: "Hello webapp!",
			wantErr:  false,
		},
		{
			name:     "path template with prefix",
			template: "{{ .TagPrefix }}/deployments/{{ .ServiceName }}.yaml",
			vars: TemplateVars{
				TagPrefix:   "dev",
				ServiceName: "webapp",
			},
			expected: "dev/deployments/webapp.yaml",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.ProcessTemplateString(tt.template, tt.vars)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestProcessor_ProcessPathTemplate(t *testing.T) {
	processor := NewProcessor()

	tests := []struct {
		name     string
		template string
		vars     TemplateVars
		expected string
		wantErr  bool
	}{
		{
			name:     "simple path",
			template: "deployments/{{ .ServiceName }}.yaml",
			vars: TemplateVars{
				ServiceName: "webapp",
			},
			expected: "deployments/webapp.yaml",
			wantErr:  false,
		},
		{
			name:     "path with prefix and default",
			template: "{{ .TagPrefix | default \"default\" }}/services/{{ .ServiceName }}.yaml",
			vars: TemplateVars{
				TagPrefix:   "staging",
				ServiceName: "api",
			},
			expected: "staging/services/api.yaml",
			wantErr:  false,
		},
		{
			name:     "path with default when prefix is empty",
			template: "{{ .TagPrefix | default \"default\" }}/configs/{{ .ServiceName }}-config.yaml",
			vars: TemplateVars{
				TagPrefix:   "", // empty prefix
				ServiceName: "worker",
			},
			expected: "default/configs/worker-config.yaml",
			wantErr:  false,
		},
		{
			name:     "path with whitespace (should be trimmed)",
			template: "  {{ .TagPrefix }}/deployments/{{ .ServiceName }}.yaml  ",
			vars: TemplateVars{
				TagPrefix:   "prod",
				ServiceName: "frontend",
			},
			expected: "prod/deployments/frontend.yaml",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.ProcessPathTemplate(tt.template, tt.vars)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
