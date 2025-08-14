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
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"sigs.k8s.io/yaml"
)

// TemplateVars represents all available template variables according to the design document
type TemplateVars struct {
	// Basic information
	ImageTag    string `json:"imageTag"`    // "v1.2.3"
	ImageDigest string `json:"imageDigest"` // "sha256:abc123..."

	// ECR URL parsing results
	RepositoryName string `json:"repositoryName"` // "my-service" or "namespace/my-service"
	Registry       string `json:"registry"`       // "123456789012.dkr.ecr.us-east-1.amazonaws.com"
	Region         string `json:"region"`         // "us-east-1"
	AccountID      string `json:"accountID"`      // "123456789012"
	FullImageName  string `json:"fullImageName"`  // Complete ECR URL

	// Hierarchical structure support
	Namespace   string `json:"namespace"`   // "namespace" (if repository is "namespace/service")
	ServiceName string `json:"serviceName"` // "my-service" (last part of hierarchy)

	// Kubernetes compatible name
	K8sCompatibleName string `json:"k8sCompatibleName"` // Kubernetes resource name format

	// Tag prefix for prefix-aware processing
	TagPrefix string `json:"tagPrefix,omitempty"` // "aaa" from "aaa-v1.0.0"

	// Additional variables from ResourceTemplate
	Variables map[string]string `json:"variables,omitempty"`
}

// Processor handles Go template processing for Kubernetes resource generation
type Processor struct {
	// Custom template functions
	funcMap template.FuncMap
}

// NewProcessor creates a new template processor
func NewProcessor() *Processor {
	return &Processor{
		funcMap: createFuncMap(),
	}
}

// ProcessTemplate processes a Go template string with provided variables
func (p *Processor) ProcessTemplate(templateContent string, vars TemplateVars) ([]byte, error) {
	// Create template with custom functions
	tmpl, err := template.New("resource").Funcs(p.funcMap).Parse(templateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	// Validate YAML syntax
	result := buf.Bytes()
	if err := p.validateYAML(result); err != nil {
		return nil, fmt.Errorf("template generated invalid YAML: %w", err)
	}

	return result, nil
}

// ProcessTemplateString processes a template string and returns the result as string
func (p *Processor) ProcessTemplateString(templateContent string, vars TemplateVars) (string, error) {
	result, err := p.ProcessTemplate(templateContent, vars)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// ProcessPathTemplate processes a path template (for relativePath in multiFiles)
func (p *Processor) ProcessPathTemplate(pathTemplate string, vars TemplateVars) (string, error) {
	// Create template with custom functions
	tmpl, err := template.New("path").Funcs(p.funcMap).Parse(pathTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse path template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return "", fmt.Errorf("failed to execute path template: %w", err)
	}

	return strings.TrimSpace(buf.String()), nil
}

// BuildTemplateVars builds template variables from image information
func (p *Processor) BuildTemplateVars(fullImageName, imageTag, imageDigest string, additionalVars map[string]string) (TemplateVars, error) {
	vars := TemplateVars{
		ImageTag:      imageTag,
		ImageDigest:   imageDigest,
		FullImageName: fullImageName,
		Variables:     additionalVars,
	}

	// Parse ECR URL
	if err := p.parseECRURL(fullImageName, &vars); err != nil {
		return vars, fmt.Errorf("failed to parse ECR URL: %w", err)
	}

	// Generate Kubernetes compatible name
	vars.K8sCompatibleName = p.sanitizeForK8s(vars.ServiceName)
	if vars.Namespace != "" {
		vars.K8sCompatibleName = p.sanitizeForK8s(vars.Namespace + "-" + vars.ServiceName)
	}

	return vars, nil
}

// BuildTemplateVarsWithPrefix builds template variables from image information including tag prefix
func (p *Processor) BuildTemplateVarsWithPrefix(fullImageName, imageTag, imageDigest, tagPrefix string, additionalVars map[string]string) (TemplateVars, error) {
	vars := TemplateVars{
		ImageTag:      imageTag,
		ImageDigest:   imageDigest,
		FullImageName: fullImageName,
		TagPrefix:     tagPrefix,
		Variables:     additionalVars,
	}

	// Parse ECR URL
	if err := p.parseECRURL(fullImageName, &vars); err != nil {
		return vars, fmt.Errorf("failed to parse ECR URL: %w", err)
	}

	// Generate Kubernetes compatible name
	vars.K8sCompatibleName = p.sanitizeForK8s(vars.ServiceName)
	if vars.Namespace != "" {
		vars.K8sCompatibleName = p.sanitizeForK8s(vars.Namespace + "-" + vars.ServiceName)
	}

	return vars, nil
}

// parseECRURL parses ECR image URL and populates template variables
func (p *Processor) parseECRURL(fullImageName string, vars *TemplateVars) error {
	// Remove tag/digest from URL for parsing
	baseURL := fullImageName
	if strings.Contains(baseURL, ":") && !strings.Contains(baseURL, "://") {
		parts := strings.Split(baseURL, ":")
		if len(parts) >= 2 {
			// Keep everything except the last part (tag)
			baseURL = strings.Join(parts[:len(parts)-1], ":")
		}
	}

	// ECR URL format: {account-id}.dkr.ecr.{region}.amazonaws.com/{repository-name}
	ecrPattern := regexp.MustCompile(`^(\d+)\.dkr\.ecr\.([^.]+)\.amazonaws\.com/(.+)$`)
	matches := ecrPattern.FindStringSubmatch(baseURL)

	if len(matches) != 4 {
		return fmt.Errorf("invalid ECR URL format: %s", fullImageName)
	}

	vars.AccountID = matches[1]
	vars.Region = matches[2]
	vars.RepositoryName = matches[3]
	vars.Registry = fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", vars.AccountID, vars.Region)

	// Parse hierarchical repository name
	if strings.Contains(vars.RepositoryName, "/") {
		parts := strings.Split(vars.RepositoryName, "/")
		vars.ServiceName = parts[len(parts)-1]
		if len(parts) > 1 {
			vars.Namespace = strings.Join(parts[:len(parts)-1], "/")
		}
	} else {
		vars.ServiceName = vars.RepositoryName
		vars.Namespace = ""
	}

	return nil
}

// sanitizeForK8s converts a name to Kubernetes DNS-1123 compliant format
func (p *Processor) sanitizeForK8s(name string) string {
	if name == "" {
		return "unnamed"
	}

	// Convert to lowercase
	sanitized := strings.ToLower(name)

	// Replace invalid characters with hyphens
	reg := regexp.MustCompile(`[^a-z0-9-]`)
	sanitized = reg.ReplaceAllString(sanitized, "-")

	// Remove leading/trailing hyphens
	sanitized = strings.Trim(sanitized, "-")

	// Limit length to 63 characters (DNS label limit)
	if len(sanitized) > 63 {
		sanitized = sanitized[:63]
		// Remove trailing hyphen if created by truncation
		sanitized = strings.TrimRight(sanitized, "-")
	}

	// Ensure it's not empty after sanitization
	if sanitized == "" {
		sanitized = "unnamed"
	}

	return sanitized
}

// validateYAML validates that the generated content is valid YAML
func (p *Processor) validateYAML(content []byte) error {
	// Split multiple YAML documents
	documents := strings.Split(string(content), "---")

	for i, doc := range documents {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue // Skip empty documents
		}

		// Try to unmarshal each document
		var temp interface{}
		if err := yaml.Unmarshal([]byte(doc), &temp); err != nil {
			return fmt.Errorf("document %d contains invalid YAML: %w", i+1, err)
		}
	}

	return nil
}

// ValidateTemplate validates template syntax without executing it
func (p *Processor) ValidateTemplate(templateContent string) error {
	_, err := template.New("validation").Funcs(p.funcMap).Parse(templateContent)
	if err != nil {
		return fmt.Errorf("invalid template syntax: %w", err)
	}
	return nil
}

// createFuncMap creates custom template functions
func createFuncMap() template.FuncMap {
	return template.FuncMap{
		// String manipulation functions
		"toLower": strings.ToLower,
		"toUpper": strings.ToUpper,
		"title":   strings.Title,
		"trim":    strings.TrimSpace,

		// String replacement functions
		"replace": func(old, new, s string) string {
			return strings.ReplaceAll(s, old, new)
		},

		// Validation functions
		"required": func(value interface{}, message string) (interface{}, error) {
			if value == nil {
				return nil, fmt.Errorf("required value missing: %s", message)
			}
			if str, ok := value.(string); ok && str == "" {
				return nil, fmt.Errorf("required value missing: %s", message)
			}
			return value, nil
		},

		// Default value function
		"default": func(defaultVal, value interface{}) interface{} {
			if value == nil {
				return defaultVal
			}
			if str, ok := value.(string); ok && str == "" {
				return defaultVal
			}
			return value
		},

		// Kubernetes naming functions
		"k8sName": func(name string) string {
			processor := NewProcessor()
			return processor.sanitizeForK8s(name)
		},

		// JSON/YAML helpers
		"toJSON": func(v interface{}) string {
			b, _ := yaml.Marshal(v)
			return string(b)
		},

		// List helpers
		"join": func(sep string, list []string) string {
			return strings.Join(list, sep)
		},

		// Conditional helpers
		"ternary": func(trueVal, falseVal interface{}, condition bool) interface{} {
			if condition {
				return trueVal
			}
			return falseVal
		},
	}
}

// SplitYAMLDocuments splits multi-document YAML into individual documents
func (p *Processor) SplitYAMLDocuments(content []byte) [][]byte {
	var documents [][]byte
	parts := strings.Split(string(content), "---")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			documents = append(documents, []byte(part))
		}
	}

	return documents
}

// ProcessorStats contains statistics about template processing
type ProcessorStats struct {
	TemplateSize     int   `json:"templateSize"`
	GeneratedSize    int   `json:"generatedSize"`
	DocumentCount    int   `json:"documentCount"`
	ProcessingTimeMs int64 `json:"processingTimeMs"`
	VariableCount    int   `json:"variableCount"`
}

// GetProcessingStats returns statistics about the last template processing
func (p *Processor) GetProcessingStats(templateContent string, result []byte, vars TemplateVars) ProcessorStats {
	documents := p.SplitYAMLDocuments(result)

	variableCount := 5 // Basic variables (ImageTag, ImageDigest, etc.)
	if vars.Variables != nil {
		variableCount += len(vars.Variables)
	}

	return ProcessorStats{
		TemplateSize:  len(templateContent),
		GeneratedSize: len(result),
		DocumentCount: len(documents),
		VariableCount: variableCount,
	}
}

// TemplateValidationResult represents the result of template validation
type TemplateValidationResult struct {
	Valid      bool     `json:"valid"`
	Errors     []string `json:"errors,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	UsedVars   []string `json:"usedVars,omitempty"`
	UnusedVars []string `json:"unusedVars,omitempty"`
}

// AnalyzeTemplate performs comprehensive template analysis
func (p *Processor) AnalyzeTemplate(templateContent string, vars TemplateVars) TemplateValidationResult {
	result := TemplateValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Validate template syntax
	if err := p.ValidateTemplate(templateContent); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
		return result
	}

	// Analyze variable usage
	p.analyzeVariableUsage(templateContent, vars, &result)

	// Try to execute template with sample data
	_, err := p.ProcessTemplate(templateContent, vars)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("template execution failed: %v", err))
	}

	return result
}

// analyzeVariableUsage analyzes which variables are used/unused in the template
func (p *Processor) analyzeVariableUsage(templateContent string, vars TemplateVars, result *TemplateValidationResult) {
	// Find all template variable references
	variablePattern := regexp.MustCompile(`\{\{\s*\.([A-Za-z][A-Za-z0-9_]*)\s*\}\}`)
	matches := variablePattern.FindAllStringSubmatch(templateContent, -1)

	usedVars := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			usedVars[match[1]] = true
		}
	}

	// Available variables through reflection would be ideal, but for now use known variables
	availableVars := []string{
		"ImageTag", "ImageDigest", "RepositoryName", "Registry", "Region",
		"AccountID", "FullImageName", "Namespace", "ServiceName", "K8sCompatibleName",
		"TagPrefix",
	}

	for _, varName := range availableVars {
		if usedVars[varName] {
			result.UsedVars = append(result.UsedVars, varName)
		} else {
			result.UnusedVars = append(result.UnusedVars, varName)
		}
	}

	// Check for Variables map usage
	if strings.Contains(templateContent, ".Variables") {
		result.UsedVars = append(result.UsedVars, "Variables")
	} else {
		result.UnusedVars = append(result.UnusedVars, "Variables")
	}
}
