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
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	automationv1beta1 "github.com/S-mishina/image-resource-controller/api/v1beta1"
	"github.com/S-mishina/image-resource-controller/internal/registry"
)

// PolicyProcessor handles image filtering based on policies
type PolicyProcessor struct{}

// NewPolicyProcessor creates a new policy processor
func NewPolicyProcessor() *PolicyProcessor {
	return &PolicyProcessor{}
}

// ApplyPolicy applies the specified policy to filter images
func (p *PolicyProcessor) ApplyPolicy(images []registry.ImageInfo, policy automationv1beta1.PolicySpec) ([]registry.ImageInfo, error) {
	if len(images) == 0 {
		return images, nil
	}

	var filtered []registry.ImageInfo
	var err error

	// Apply policy in priority order
	switch {
	case policy.Semver != nil:
		filtered, err = p.applySemverPolicy(images, *policy.Semver)
	case policy.Pattern != nil:
		filtered, err = p.applyPatternPolicy(images, *policy.Pattern)
	case policy.Alphabetical != nil:
		filtered, err = p.applyAlphabeticalPolicy(images, *policy.Alphabetical)
	default:
		// No policy specified, return all images
		filtered = images
	}

	if err != nil {
		return nil, fmt.Errorf("failed to apply policy: %w", err)
	}

	return filtered, nil
}

// applySemverPolicy filters images based on semantic version constraints
func (p *PolicyProcessor) applySemverPolicy(images []registry.ImageInfo, policy automationv1beta1.SemverPolicy) ([]registry.ImageInfo, error) {
	constraint, err := semver.NewConstraint(policy.Range)
	if err != nil {
		return nil, fmt.Errorf("invalid semver constraint '%s': %w", policy.Range, err)
	}

	var semverImages []SemverImage
	var nonSemverImages []registry.ImageInfo

	// Separate semantic version images from non-semantic version images
	for _, img := range images {
		if version, err := semver.NewVersion(strings.TrimPrefix(img.Tag, "v")); err == nil {
			if constraint.Check(version) {
				semverImages = append(semverImages, SemverImage{
					ImageInfo: img,
					Version:   version,
				})
			}
		} else {
			// Keep non-semver images as they might be important (like "latest", "stable")
			nonSemverImages = append(nonSemverImages, img)
		}
	}

	// Sort semver images by version (newest first)
	sort.Slice(semverImages, func(i, j int) bool {
		return semverImages[i].Version.GreaterThan(semverImages[j].Version)
	})

	// Convert back to ImageInfo
	var result []registry.ImageInfo
	for _, semverImg := range semverImages {
		result = append(result, semverImg.ImageInfo)
	}

	// Add non-semver images at the end
	result = append(result, nonSemverImages...)

	return result, nil
}

// applyPatternPolicy filters images based on regex pattern
func (p *PolicyProcessor) applyPatternPolicy(images []registry.ImageInfo, policy automationv1beta1.PatternPolicy) ([]registry.ImageInfo, error) {
	regex, err := regexp.Compile(policy.Regex)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern '%s': %w", policy.Regex, err)
	}

	var filtered []registry.ImageInfo
	for _, img := range images {
		if regex.MatchString(img.Tag) {
			filtered = append(filtered, img)
		}
	}

	return filtered, nil
}

// ApplyPatternPolicyWithPrefix filters images and extracts prefixes from regex capture groups
func (p *PolicyProcessor) ApplyPatternPolicyWithPrefix(images []registry.ImageInfo, policy automationv1beta1.PatternPolicy) ([]registry.ImageInfo, map[string]string, error) {
	// Validate regex pattern
	if policy.Regex == "" {
		return nil, nil, fmt.Errorf("regex pattern cannot be empty")
	}

	regex, err := regexp.Compile(policy.Regex)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid regex pattern '%s': %w", policy.Regex, err)
	}

	var filtered []registry.ImageInfo
	var prefixMap map[string]string

	if policy.ExtractPrefix {
		prefixMap = make(map[string]string) // tag -> prefix mapping
	}

	// Track statistics for logging
	matchCount := 0
	prefixExtractCount := 0
	noCapturegroupCount := 0

	for _, img := range images {
		if img.Tag == "" {
			// Skip empty tags
			continue
		}

		matches := regex.FindStringSubmatch(img.Tag)
		if len(matches) > 0 {
			// マッチした
			filtered = append(filtered, img)
			matchCount++

			// extractPrefix=true かつ キャプチャグループがある場合
			if policy.ExtractPrefix {
				if len(matches) > 1 && matches[1] != "" {
					prefixMap[img.Tag] = matches[1] // 最初のキャプチャグループ
					prefixExtractCount++
				} else {
					// No capture groups or empty capture group
					noCapturegroupCount++
				}
			}
		}
	}

	// Log statistics if extractPrefix is enabled
	if policy.ExtractPrefix {
		// Note: In a real scenario, we'd use proper logging with context
		// For now, we'll add debug information in error cases
		if noCapturegroupCount > 0 && prefixExtractCount == 0 {
			return nil, nil, fmt.Errorf("extractPrefix is enabled but regex pattern '%s' has no capture groups or all capture groups are empty", policy.Regex)
		}
	}

	return filtered, prefixMap, nil
}

// applyAlphabeticalPolicy selects the best image alphabetically by tag
func (p *PolicyProcessor) applyAlphabeticalPolicy(images []registry.ImageInfo, policy automationv1beta1.AlphabeticalPolicy) ([]registry.ImageInfo, error) {
	if len(images) == 0 {
		return images, nil
	}

	// Create a copy to avoid modifying the original slice
	sorted := make([]registry.ImageInfo, len(images))
	copy(sorted, images)

	// Sort based on the specified order
	switch policy.Order {
	case "desc":
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Tag > sorted[j].Tag
		})
	case "asc", "": // default to ascending
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Tag < sorted[j].Tag
		})
	default:
		return nil, fmt.Errorf("invalid alphabetical order '%s', must be 'asc' or 'desc'", policy.Order)
	}

	// Return only the first image (the best match according to the policy)
	return []registry.ImageInfo{sorted[0]}, nil
}

// GetPolicyDescription returns a human-readable description of the policy
func (p *PolicyProcessor) GetPolicyDescription(policy automationv1beta1.PolicySpec) string {
	switch {
	case policy.Semver != nil:
		return fmt.Sprintf("Semantic version constraint: %s", policy.Semver.Range)
	case policy.Pattern != nil:
		return fmt.Sprintf("Regex pattern: %s", policy.Pattern.Regex)
	case policy.Alphabetical != nil:
		order := policy.Alphabetical.Order
		if order == "" {
			order = "asc"
		}
		return fmt.Sprintf("Alphabetical order: %s", order)
	default:
		return "No policy specified"
	}
}

// ValidatePolicy validates if the policy configuration is correct
func (p *PolicyProcessor) ValidatePolicy(policy automationv1beta1.PolicySpec) error {
	// Count how many policies are specified
	policyCount := 0
	if policy.Semver != nil {
		policyCount++
	}
	if policy.Pattern != nil {
		policyCount++
	}
	if policy.Alphabetical != nil {
		policyCount++
	}

	if policyCount > 1 {
		return fmt.Errorf("multiple policies specified, only one policy type is allowed")
	}

	if policyCount == 0 {
		return fmt.Errorf("no policy specified, at least one policy type is required")
	}

	// Validate individual policies
	if policy.Semver != nil {
		if policy.Semver.Range == "" {
			return fmt.Errorf("semver policy requires a non-empty range")
		}
		// Test if the constraint is valid
		_, err := semver.NewConstraint(policy.Semver.Range)
		if err != nil {
			return fmt.Errorf("invalid semver constraint '%s': %w", policy.Semver.Range, err)
		}
	}

	if policy.Pattern != nil {
		if policy.Pattern.Regex == "" {
			return fmt.Errorf("pattern policy requires a non-empty regex")
		}
		// Test if the regex is valid
		_, err := regexp.Compile(policy.Pattern.Regex)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", policy.Pattern.Regex, err)
		}
	}

	if policy.Alphabetical != nil {
		if policy.Alphabetical.Order != "" && policy.Alphabetical.Order != "asc" && policy.Alphabetical.Order != "desc" {
			return fmt.Errorf("alphabetical policy order must be 'asc' or 'desc', got '%s'", policy.Alphabetical.Order)
		}
	}

	return nil
}

// SemverImage represents an image with semantic version information
type SemverImage struct {
	ImageInfo registry.ImageInfo
	Version   *semver.Version
}

// PolicyStats represents statistics about policy application
type PolicyStats struct {
	TotalImages    int
	FilteredImages int
	PolicyType     string
	PolicyDetails  string
}

// GetPolicyStats returns statistics about how the policy was applied
func (p *PolicyProcessor) GetPolicyStats(originalImages, filteredImages []registry.ImageInfo, policy automationv1beta1.PolicySpec) PolicyStats {
	stats := PolicyStats{
		TotalImages:    len(originalImages),
		FilteredImages: len(filteredImages),
		PolicyDetails:  p.GetPolicyDescription(policy),
	}

	switch {
	case policy.Semver != nil:
		stats.PolicyType = "semver"
	case policy.Pattern != nil:
		stats.PolicyType = "pattern"
	case policy.Alphabetical != nil:
		stats.PolicyType = "alphabetical"
	default:
		stats.PolicyType = "none"
	}

	return stats
}
