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

package policy

import (
	"testing"

	automationv1beta1 "github.com/S-mishina/image-resource-controller/api/v1beta1"
	"github.com/S-mishina/image-resource-controller/internal/registry"
)

func TestApplyPatternPolicyWithPrefix(t *testing.T) {
	processor := NewPolicyProcessor()

	testImages := []registry.ImageInfo{
		{Tag: "dev-v1.0.0"},
		{Tag: "staging-v2.1.0"},
		{Tag: "prod-v1.5.0"},
		{Tag: "invalid-tag"},
		{Tag: "feature-branch-test"},
	}

	tests := []struct {
		name           string
		policy         automationv1beta1.PatternPolicy
		expectedCount  int
		expectedPrefix map[string]string
	}{
		{
			name: "Extract environment prefix",
			policy: automationv1beta1.PatternPolicy{
				Regex:         "^(dev|staging|prod)-v\\d+\\.\\d+\\.\\d+$",
				ExtractPrefix: true,
			},
			expectedCount: 3,
			expectedPrefix: map[string]string{
				"dev-v1.0.0":     "dev",
				"staging-v2.1.0": "staging",
				"prod-v1.5.0":    "prod",
			},
		},
		{
			name: "Extract feature prefix",
			policy: automationv1beta1.PatternPolicy{
				Regex:         "^(feature)-.*$",
				ExtractPrefix: true,
			},
			expectedCount: 1,
			expectedPrefix: map[string]string{
				"feature-branch-test": "feature",
			},
		},
		{
			name: "No prefix extraction",
			policy: automationv1beta1.PatternPolicy{
				Regex:         "^(dev|staging|prod)-v\\d+\\.\\d+\\.\\d+$",
				ExtractPrefix: false,
			},
			expectedCount:  3,
			expectedPrefix: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, prefixMap, err := processor.ApplyPatternPolicyWithPrefix(testImages, tt.policy)
			if err != nil {
				t.Fatalf("ApplyPatternPolicyWithPrefix() error = %v", err)
			}

			if len(filtered) != tt.expectedCount {
				t.Errorf("ApplyPatternPolicyWithPrefix() filtered count = %v, want %v", len(filtered), tt.expectedCount)
			}

			if tt.policy.ExtractPrefix {
				if prefixMap == nil {
					t.Errorf("ApplyPatternPolicyWithPrefix() prefixMap is nil, but extractPrefix is true")
					return
				}

				for tag, expectedPrefix := range tt.expectedPrefix {
					if actualPrefix, exists := prefixMap[tag]; !exists {
						t.Errorf("ApplyPatternPolicyWithPrefix() prefixMap missing tag %s", tag)
					} else if actualPrefix != expectedPrefix {
						t.Errorf("ApplyPatternPolicyWithPrefix() prefixMap[%s] = %v, want %v", tag, actualPrefix, expectedPrefix)
					}
				}
			} else {
				if prefixMap != nil {
					t.Errorf("ApplyPatternPolicyWithPrefix() prefixMap should be nil when extractPrefix is false")
				}
			}
		})
	}
}

func TestApplyPatternPolicyWithPrefixEdgeCases(t *testing.T) {
	processor := NewPolicyProcessor()

	tests := []struct {
		name   string
		images []registry.ImageInfo
		policy automationv1beta1.PatternPolicy
		want   map[string]string
	}{
		{
			name: "No capture groups",
			images: []registry.ImageInfo{
				{Tag: "v1.0.0"},
			},
			policy: automationv1beta1.PatternPolicy{
				Regex:         "^v\\d+\\.\\d+\\.\\d+$", // No capture groups
				ExtractPrefix: true,
			},
			want: nil, // Should return error due to no capture groups
		},
		{
			name: "Multiple capture groups - use first",
			images: []registry.ImageInfo{
				{Tag: "dev-feature-v1.0.0"},
			},
			policy: automationv1beta1.PatternPolicy{
				Regex:         "^(dev|staging|prod)-(feature|hotfix)-v\\d+\\.\\d+\\.\\d+$",
				ExtractPrefix: true,
			},
			want: map[string]string{
				"dev-feature-v1.0.0": "dev", // First capture group
			},
		},
		{
			name: "Invalid regex",
			images: []registry.ImageInfo{
				{Tag: "any-tag"},
			},
			policy: automationv1beta1.PatternPolicy{
				Regex:         "[invalid", // Invalid regex
				ExtractPrefix: true,
			},
			want: nil, // Should return error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, prefixMap, err := processor.ApplyPatternPolicyWithPrefix(tt.images, tt.policy)

			if tt.name == "Invalid regex" || tt.name == "No capture groups" {
				if err == nil {
					t.Errorf("ApplyPatternPolicyWithPrefix() expected error for %s", tt.name)
				}
				return
			}

			if err != nil {
				t.Fatalf("ApplyPatternPolicyWithPrefix() unexpected error = %v", err)
			}

			if len(prefixMap) != len(tt.want) {
				t.Errorf("ApplyPatternPolicyWithPrefix() prefixMap length = %v, want %v", len(prefixMap), len(tt.want))
			}

			for tag, expectedPrefix := range tt.want {
				if actualPrefix, exists := prefixMap[tag]; !exists {
					t.Errorf("ApplyPatternPolicyWithPrefix() prefixMap missing tag %s", tag)
				} else if actualPrefix != expectedPrefix {
					t.Errorf("ApplyPatternPolicyWithPrefix() prefixMap[%s] = %v, want %v", tag, actualPrefix, expectedPrefix)
				}
			}
		})
	}
}
