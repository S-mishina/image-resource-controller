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

package k8s

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ResourceInfo represents information about a Kubernetes resource using an image
type ResourceInfo struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Image     string `json:"image"`
	Container string `json:"container"`
}

// ImageUsageCache caches the mapping of images to Kubernetes resources
type ImageUsageCache struct {
	mu           sync.RWMutex
	imageToUsage map[string][]ResourceInfo // image name -> resources using it
	lastUpdated  time.Time
	updateTTL    time.Duration
}

// NewImageUsageCache creates a new image usage cache
func NewImageUsageCache(updateTTL time.Duration) *ImageUsageCache {
	if updateTTL == 0 {
		updateTTL = 5 * time.Minute // Default TTL
	}

	return &ImageUsageCache{
		imageToUsage: make(map[string][]ResourceInfo),
		updateTTL:    updateTTL,
	}
}

// IsExpired checks if the cache needs to be refreshed
func (c *ImageUsageCache) IsExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return time.Since(c.lastUpdated) > c.updateTTL
}

// GetImageUsage retrieves the usage information for a specific image
func (c *ImageUsageCache) GetImageUsage(imageName string) []ResourceInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	usage, exists := c.imageToUsage[imageName]
	if !exists {
		return []ResourceInfo{}
	}

	// Return a copy to avoid race conditions
	result := make([]ResourceInfo, len(usage))
	copy(result, usage)
	return result
}

// UpdateCache updates the entire cache with new data
func (c *ImageUsageCache) UpdateCache(imageUsage map[string][]ResourceInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.imageToUsage = imageUsage
	c.lastUpdated = time.Now()
}

// GetCacheStats returns statistics about the cache
func (c *ImageUsageCache) GetCacheStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalResources := 0
	for _, resources := range c.imageToUsage {
		totalResources += len(resources)
	}

	return CacheStats{
		TotalImages:    len(c.imageToUsage),
		TotalResources: totalResources,
		LastUpdated:    c.lastUpdated,
		IsExpired:      time.Since(c.lastUpdated) > c.updateTTL,
	}
}

// CacheStats represents statistics about the image usage cache
type CacheStats struct {
	TotalImages    int       `json:"totalImages"`
	TotalResources int       `json:"totalResources"`
	LastUpdated    time.Time `json:"lastUpdated"`
	IsExpired      bool      `json:"isExpired"`
}

// ExistenceChecker checks if images are already used by existing Kubernetes resources
type ExistenceChecker struct {
	client client.Client
	scheme *runtime.Scheme
	cache  *ImageUsageCache
}

// NewExistenceChecker creates a new existence checker
func NewExistenceChecker(client client.Client, scheme *runtime.Scheme) *ExistenceChecker {
	return &ExistenceChecker{
		client: client,
		scheme: scheme,
		cache:  NewImageUsageCache(5 * time.Minute),
	}
}

// CheckImageExists checks if the specified image is already used by existing Kubernetes resources
func (ec *ExistenceChecker) CheckImageExists(ctx context.Context, imageName string) (bool, []ResourceInfo, error) {
	logger := log.FromContext(ctx)

	// Update cache if expired
	if ec.cache.IsExpired() {
		logger.Info("Image usage cache is expired, refreshing...")
		if err := ec.refreshCache(ctx); err != nil {
			logger.Error(err, "Failed to refresh image usage cache")
			// Continue with stale cache rather than failing completely
		}
	}

	// Extract base image name for lookup
	extractedName := ec.extractImageName(imageName)

	usage := ec.cache.GetImageUsage(extractedName)
	exists := len(usage) > 0

	logger.Info("Image existence check completed",
		"imageName", imageName,
		"exists", exists,
		"usageCount", len(usage))

	return exists, usage, nil
}

// refreshCache scans the entire cluster and updates the cache
func (ec *ExistenceChecker) refreshCache(ctx context.Context) error {
	logger := log.FromContext(ctx)
	logger.Info("Starting cluster-wide image usage scan")

	imageUsage := make(map[string][]ResourceInfo)

	// Scan Deployments
	if err := ec.scanDeployments(ctx, imageUsage); err != nil {
		return fmt.Errorf("failed to scan Deployments: %w", err)
	}

	// Scan StatefulSets
	if err := ec.scanStatefulSets(ctx, imageUsage); err != nil {
		return fmt.Errorf("failed to scan StatefulSets: %w", err)
	}

	// Scan DaemonSets
	if err := ec.scanDaemonSets(ctx, imageUsage); err != nil {
		return fmt.Errorf("failed to scan DaemonSets: %w", err)
	}

	// Scan Jobs
	if err := ec.scanJobs(ctx, imageUsage); err != nil {
		return fmt.Errorf("failed to scan Jobs: %w", err)
	}

	// Scan CronJobs
	if err := ec.scanCronJobs(ctx, imageUsage); err != nil {
		return fmt.Errorf("failed to scan CronJobs: %w", err)
	}

	// Update cache
	ec.cache.UpdateCache(imageUsage)

	stats := ec.cache.GetCacheStats()
	logger.Info("Cluster-wide image usage scan completed",
		"totalImages", stats.TotalImages,
		"totalResources", stats.TotalResources)

	return nil
}

// scanDeployments scans all Deployments for image usage
func (ec *ExistenceChecker) scanDeployments(ctx context.Context, imageUsage map[string][]ResourceInfo) error {
	var deployments appsv1.DeploymentList
	if err := ec.client.List(ctx, &deployments); err != nil {
		return fmt.Errorf("failed to list Deployments: %w", err)
	}

	for _, deployment := range deployments.Items {
		ec.extractImagesFromPodSpec(&deployment.Spec.Template.Spec, deployment.Namespace, deployment.Name, "Deployment", imageUsage)
	}

	return nil
}

// scanStatefulSets scans all StatefulSets for image usage
func (ec *ExistenceChecker) scanStatefulSets(ctx context.Context, imageUsage map[string][]ResourceInfo) error {
	var statefulSets appsv1.StatefulSetList
	if err := ec.client.List(ctx, &statefulSets); err != nil {
		return fmt.Errorf("failed to list StatefulSets: %w", err)
	}

	for _, statefulSet := range statefulSets.Items {
		ec.extractImagesFromPodSpec(&statefulSet.Spec.Template.Spec, statefulSet.Namespace, statefulSet.Name, "StatefulSet", imageUsage)
	}

	return nil
}

// scanDaemonSets scans all DaemonSets for image usage
func (ec *ExistenceChecker) scanDaemonSets(ctx context.Context, imageUsage map[string][]ResourceInfo) error {
	var daemonSets appsv1.DaemonSetList
	if err := ec.client.List(ctx, &daemonSets); err != nil {
		return fmt.Errorf("failed to list DaemonSets: %w", err)
	}

	for _, daemonSet := range daemonSets.Items {
		ec.extractImagesFromPodSpec(&daemonSet.Spec.Template.Spec, daemonSet.Namespace, daemonSet.Name, "DaemonSet", imageUsage)
	}

	return nil
}

// scanJobs scans all Jobs for image usage
func (ec *ExistenceChecker) scanJobs(ctx context.Context, imageUsage map[string][]ResourceInfo) error {
	var jobs batchv1.JobList
	if err := ec.client.List(ctx, &jobs); err != nil {
		return fmt.Errorf("failed to list Jobs: %w", err)
	}

	for _, job := range jobs.Items {
		ec.extractImagesFromPodSpec(&job.Spec.Template.Spec, job.Namespace, job.Name, "Job", imageUsage)
	}

	return nil
}

// scanCronJobs scans all CronJobs for image usage
func (ec *ExistenceChecker) scanCronJobs(ctx context.Context, imageUsage map[string][]ResourceInfo) error {
	var cronJobs batchv1.CronJobList
	if err := ec.client.List(ctx, &cronJobs); err != nil {
		return fmt.Errorf("failed to list CronJobs: %w", err)
	}

	for _, cronJob := range cronJobs.Items {
		ec.extractImagesFromPodSpec(&cronJob.Spec.JobTemplate.Spec.Template.Spec, cronJob.Namespace, cronJob.Name, "CronJob", imageUsage)
	}

	return nil
}

// extractImagesFromPodSpec extracts all images from a PodSpec and adds them to the usage map
func (ec *ExistenceChecker) extractImagesFromPodSpec(podSpec *corev1.PodSpec, namespace, name, kind string, imageUsage map[string][]ResourceInfo) {
	// Extract from regular containers
	for _, container := range podSpec.Containers {
		ec.addImageUsage(container.Image, container.Name, namespace, name, kind, imageUsage)
	}

	// Extract from init containers
	for _, container := range podSpec.InitContainers {
		ec.addImageUsage(container.Image, container.Name, namespace, name, kind, imageUsage)
	}

	// Extract from ephemeral containers (if any)
	for _, container := range podSpec.EphemeralContainers {
		ec.addImageUsage(container.Image, container.Name, namespace, name, kind, imageUsage)
	}
}

// addImageUsage adds an image usage entry to the usage map
func (ec *ExistenceChecker) addImageUsage(fullImageName, containerName, namespace, resourceName, kind string, imageUsage map[string][]ResourceInfo) {
	if fullImageName == "" {
		return
	}

	// Extract the image name without tag and registry for matching
	imageName := ec.extractImageName(fullImageName)

	resourceInfo := ResourceInfo{
		Namespace: namespace,
		Name:      resourceName,
		Kind:      kind,
		Image:     fullImageName,
		Container: containerName,
	}

	imageUsage[imageName] = append(imageUsage[imageName], resourceInfo)
}

// extractImageName extracts the base image name from a full image reference
// Examples:
// "nginx:latest" -> "nginx"
// "registry.example.com/namespace/service:v1.0.0" -> "service"
// "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3" -> "my-service"
func (ec *ExistenceChecker) extractImageName(fullImageName string) string {
	imagePart := fullImageName

	// Handle digest format: image:tag@sha256:digest
	if strings.Contains(imagePart, "@") {
		imagePart = strings.Split(imagePart, "@")[0]
	}

	// Remove tag (:tag)
	if strings.Contains(imagePart, ":") {
		// Split by : and take everything except the last part (which is the tag)
		parts := strings.Split(imagePart, ":")
		if len(parts) > 1 {
			// Check if the last part looks like a tag (not a port number)
			lastPart := parts[len(parts)-1]
			// If it contains only alphanumeric chars, dots, dashes - it's likely a tag
			if len(lastPart) > 0 && !strings.Contains(lastPart, "/") {
				imagePart = strings.Join(parts[:len(parts)-1], ":")
			}
		}
	}

	// Remove registry part (everything before the last /)
	if strings.Contains(imagePart, "/") {
		parts := strings.Split(imagePart, "/")
		return parts[len(parts)-1] // Return the last part (image name)
	}

	return imagePart
}

// GetCacheStats returns current cache statistics
func (ec *ExistenceChecker) GetCacheStats() CacheStats {
	return ec.cache.GetCacheStats()
}

// CheckImageExistsWithTagPrefix checks with tag prefix awareness for version management
func (ec *ExistenceChecker) CheckImageExistsWithTagPrefix(ctx context.Context, imageName string, tagPrefix string) (bool, []ResourceInfo, error) {
	logger := log.FromContext(ctx)

	// Validate input parameters
	if imageName == "" {
		return false, []ResourceInfo{}, fmt.Errorf("imageName cannot be empty")
	}

	logger.V(1).Info("Starting prefix-aware image existence check",
		"imageName", imageName,
		"tagPrefix", tagPrefix)

	// Update cache if expired
	if ec.cache.IsExpired() {
		logger.Info("Image usage cache is expired, refreshing...")
		if err := ec.refreshCache(ctx); err != nil {
			logger.Error(err, "Failed to refresh image usage cache")
			// Continue with stale cache rather than failing completely
		}
	}

	// Get base image usage
	usage := ec.cache.GetImageUsage(imageName)

	if len(usage) == 0 {
		// No existing resources for this image name
		logger.V(1).Info("No existing resources found for image",
			"imageName", imageName)
		return false, []ResourceInfo{}, nil
	}

	logger.V(1).Info("Found existing resources for image",
		"imageName", imageName,
		"totalResources", len(usage))

	// If tagPrefix is empty, fall back to traditional check
	if tagPrefix == "" {
		logger.V(1).Info("No tagPrefix specified, using traditional existence check",
			"imageName", imageName,
			"resourceCount", len(usage))
		exists := len(usage) > 0
		return exists, usage, nil
	}

	// Check for same prefix using flexible extraction
	matchingResources := []ResourceInfo{}
	prefixStats := make(map[string]int) // Track prefix distribution

	for _, resource := range usage {
		// Extract tag from resource image
		existingTag := ec.extractTag(resource.Image)
		if existingTag == "" {
			logger.V(1).Info("Skipping resource with empty tag",
				"resourceName", resource.Name,
				"resourceKind", resource.Kind,
				"fullImage", resource.Image)
			continue
		}

		// Extract prefix from existing tag and compare
		existingPrefix := ec.extractPrefixFromTag(existingTag)
		prefixStats[existingPrefix]++

		logger.V(2).Info("Comparing tag prefixes",
			"existingTag", existingTag,
			"existingPrefix", existingPrefix,
			"newTagPrefix", tagPrefix,
			"resourceName", resource.Name)

		if existingPrefix == tagPrefix {
			matchingResources = append(matchingResources, resource)
			logger.Info("Found existing resource with same tag prefix",
				"imageName", imageName,
				"existingTag", existingTag,
				"existingPrefix", existingPrefix,
				"newTagPrefix", tagPrefix,
				"resourceName", resource.Name,
				"resourceKind", resource.Kind,
				"resourceNamespace", resource.Namespace)
		}
	}

	exists := len(matchingResources) > 0

	// Enhanced logging with prefix statistics
	logger.Info("Tag prefix existence check completed",
		"imageName", imageName,
		"tagPrefix", tagPrefix,
		"exists", exists,
		"matchingResourcesCount", len(matchingResources),
		"totalResourcesCount", len(usage),
		"prefixDistribution", prefixStats)

	// Log detailed results for debugging
	if len(matchingResources) > 0 {
		logger.V(1).Info("Prefix match found - delegating to Flux for version management",
			"reason", "Same prefix exists in cluster")
	} else {
		logger.V(1).Info("No prefix match found - will create new resource",
			"reason", "Different or no matching prefix in cluster")
	}

	return exists, matchingResources, nil
}

// extractPrefixFromTag extracts prefix from tag using multiple separators
func (ec *ExistenceChecker) extractPrefixFromTag(tag string) string {
	// 優先順位でセパレータを試す
	separators := []string{"-", "_", ".", "/"}

	for _, sep := range separators {
		if strings.Contains(tag, sep) {
			parts := strings.Split(tag, sep)
			if len(parts) > 0 && parts[0] != "" {
				return parts[0] // 最初の部分をプレフィックスとする
			}
		}
	}

	// セパレータがない場合は全体をプレフィックスとする
	return tag
}

// extractTag extracts tag from full image name
func (ec *ExistenceChecker) extractTag(fullImageName string) string {
	// "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:aaa-v1.0.0"
	// -> "aaa-v1.0.0"

	if strings.Contains(fullImageName, ":") {
		parts := strings.Split(fullImageName, ":")
		if len(parts) > 1 {
			tag := parts[len(parts)-1]
			// Remove digest if present (@sha256:...)
			if strings.Contains(tag, "@") {
				tag = strings.Split(tag, "@")[0]
			}
			return tag
		}
	}
	return ""
}

// ForceRefresh forces a cache refresh regardless of TTL
func (ec *ExistenceChecker) ForceRefresh(ctx context.Context) error {
	return ec.refreshCache(ctx)
}
