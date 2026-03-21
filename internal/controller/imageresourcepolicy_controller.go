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
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	automationv1beta1 "github.com/S-mishina/image-resource-controller/api/v1beta1"
	"github.com/S-mishina/image-resource-controller/internal/policy"
	"github.com/S-mishina/image-resource-controller/internal/registry"
)

const (
	// ConditionReady indicates whether the resource is ready.
	ConditionReady = "Ready"
	// ConditionSuspended indicates whether the resource is suspended.
	ConditionSuspended = "Suspended"

	// ReasonSuspended indicates the resource is suspended.
	ReasonSuspended = "Suspended"
	// ReasonReconciling indicates the resource is being reconciled.
	ReasonReconciling = "Reconciling"
	// ReasonReconcileSuccess indicates the reconciliation succeeded.
	ReasonReconcileSuccess = "ReconcileSuccess"
	// ReasonReconcileError indicates the reconciliation failed.
	ReasonReconcileError = "ReconcileError"

	// DefaultRequeueInterval is the default requeue interval.
	DefaultRequeueInterval = 5 * time.Minute
	// SuspendedRequeueInterval is the requeue interval for suspended policies.
	SuspendedRequeueInterval = 30 * time.Minute
	// ErrorRequeueInterval is the requeue interval on error.
	ErrorRequeueInterval = 2 * time.Minute

	// patternTypeRepository is the constant for "repository" pattern type.
	patternTypeRepository = "repository"
)

// ImageResourcePolicyReconciler reconciles a ImageResourcePolicy object
type ImageResourcePolicyReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	RegistryFactory registry.ImageRegistryFactory
	PolicyProcessor *policy.PolicyProcessor
}

// +kubebuilder:rbac:groups=automation.gitops.io,resources=imageresourcepolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automation.gitops.io,resources=imageresourcepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automation.gitops.io,resources=imageresourcepolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=automation.gitops.io,resources=imagedetecteds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automation.gitops.io,resources=imagedetecteds/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// NOTE: This controller implements ECR image scanning and ImageDetected resource creation
// based on ImageResourcePolicy specifications. The reconcile loop handles:
// - ECR authentication and repository scanning
// - Image filtering based on policies (alphabetical, pattern, numeric, date)
// - ImageDetected resource creation and management
// - Per-repository processing for complex scanning scenarios
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.18.4/pkg/reconcile
func (r *ImageResourcePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Fetch the ImageResourcePolicy instance
	var policy automationv1beta1.ImageResourcePolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if errors.IsNotFound(err) {
			// Resource was deleted, nothing to do
			logger.Info("ImageResourcePolicy resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request
		logger.Error(err, "Failed to get ImageResourcePolicy")
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling ImageResourcePolicy",
		"name", policy.Name,
		"namespace", policy.Namespace,
		"registryType", r.getRegistryType(&policy),
		"generation", policy.Generation)

	// 2. Check if the policy is suspended
	if policy.Spec.Suspend {
		logger.Info("ImageResourcePolicy is suspended, skipping scan")
		return r.updateStatusSuspended(ctx, &policy)
	}

	// 3. Execute registry scanning logic
	return r.executeRegistryScan(ctx, &policy)
}

// updateStatusSuspended updates status when the policy is suspended
func (r *ImageResourcePolicyReconciler) updateStatusSuspended(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Update ObservedGeneration
	policy.Status.ObservedGeneration = policy.Generation

	// Set Suspended condition
	condition := metav1.Condition{
		Type:               ConditionSuspended,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonSuspended,
		Message:            "ImageResourcePolicy is suspended",
	}
	r.setCondition(&policy.Status.Conditions, condition)

	// Set Ready condition to False
	readyCondition := metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonSuspended,
		Message:            "ImageResourcePolicy is suspended",
	}
	r.setCondition(&policy.Status.Conditions, readyCondition)

	if err := r.Status().Update(ctx, policy); err != nil {
		logger.Error(err, "Failed to update ImageResourcePolicy status for suspended state")
		return ctrl.Result{RequeueAfter: ErrorRequeueInterval}, err
	}

	logger.Info("ImageResourcePolicy status updated", "state", "suspended")
	// Requeue after longer interval for suspended policies
	return ctrl.Result{RequeueAfter: SuspendedRequeueInterval}, nil
}

// setCondition sets or updates a condition in the condition slice
func (r *ImageResourcePolicyReconciler) setCondition(conditions *[]metav1.Condition, newCondition metav1.Condition) {
	for i, condition := range *conditions {
		if condition.Type == newCondition.Type {
			// Update existing condition
			(*conditions)[i] = newCondition
			return
		}
	}
	// Add new condition
	*conditions = append(*conditions, newCondition)
}

// removeCondition removes a condition from the condition slice
func (r *ImageResourcePolicyReconciler) removeCondition(conditions *[]metav1.Condition, conditionType string) {
	for i, condition := range *conditions {
		if condition.Type == conditionType {
			*conditions = append((*conditions)[:i], (*conditions)[i+1:]...)
			return
		}
	}
}

// executeRegistryScan performs the actual registry scanning and ImageDetected creation
func (r *ImageResourcePolicyReconciler) executeRegistryScan(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Validate repository configuration
	pattern, patternType, region, maxRepos, err := r.extractScanParams(policy)
	if err != nil {
		return r.updateStatusError(ctx, policy, fmt.Sprintf("Invalid repository configuration: %v", err))
	}

	logger.Info("Starting pattern scan",
		"pattern", pattern,
		"patternType", patternType,
		"registryType", r.getRegistryType(policy))

	// 2. Create registry client
	registryClient, err := r.createRegistryClient(policy)
	if err != nil {
		return r.updateStatusError(ctx, policy, fmt.Sprintf("Failed to create registry client: %v", err))
	}

	// 3. Scan repositories by pattern
	var images []registry.ImageInfo

	switch patternType {
	case patternTypeRepository:
		images, err = registryClient.ScanRepositoriesByPattern(ctx, region, pattern, maxRepos)
		if err != nil {
			return r.updateStatusError(ctx, policy, fmt.Sprintf("Failed to scan repositories by pattern: %v", err))
		}

	case "imageName":
		images, err = registryClient.ScanAllRepositoriesByImageName(ctx, region, pattern, maxRepos)
		if err != nil {
			return r.updateStatusError(ctx, policy, fmt.Sprintf("Failed to scan all repositories for image name pattern: %v", err))
		}

	case "image":
		images, err = registryClient.ScanByImagePattern(ctx, region, pattern, maxRepos)
		if err != nil {
			return r.updateStatusError(ctx, policy, fmt.Sprintf("Failed to scan by image pattern: %v", err))
		}

	default:
		return r.updateStatusError(ctx, policy, fmt.Sprintf("Unknown pattern type '%s'", patternType))
	}

	logger.Info("Found images from pattern scan", "count", len(images), "pattern", pattern)

	// 3. Apply policy filtering and create ImageDetected resources
	var createdCount int

	if policy.Spec.Policy.PerRepository {
		// Per-repository processing: apply policy to each repository separately
		var perRepoErr error
		createdCount, perRepoErr = r.processImagesPerRepository(ctx, policy, registryClient)
		if perRepoErr != nil {
			return r.updateStatusError(ctx, policy, fmt.Sprintf("Failed to process images per repository: %v", perRepoErr))
		}
	} else {
		// Cross-repository processing: apply policy across all images (existing behavior)
		filteredImages := r.applyPolicyFilter(images, policy.Spec.Policy)
		logger.Info("Images after policy filtering", "count", len(filteredImages))

		// Create ImageDetected CRDs for filtered images
		for _, img := range filteredImages {
			created, createErr := r.createImageDetectedIfNotExists(ctx, policy, img)
			if createErr != nil {
				logger.Error(createErr, "Failed to create ImageDetected", "image", img.Name, "tag", img.Tag)
				// Continue with other images instead of failing completely
				continue
			}
			if created {
				createdCount++
			}
		}
	}

	// 5. Clean up expired ImageDetected resources
	cleanedCount, err := r.cleanupExpiredImageDetected(ctx, policy)
	if err != nil {
		logger.Error(err, "Failed to cleanup expired ImageDetected resources")
		// Continue even if cleanup fails
	} else if cleanedCount > 0 {
		logger.Info("Cleaned up expired ImageDetected resources", "cleanedCount", cleanedCount)
	}

	// 6. Update status with scan results
	return r.updateStatusScanSuccess(ctx, policy, len(images), createdCount)
}

// getRegistryType returns the registry type string for the policy
func (r *ImageResourcePolicyReconciler) getRegistryType(policy *automationv1beta1.ImageResourcePolicy) string {
	if policy.Spec.GenericRegistry != nil {
		return "generic"
	}
	return "ecr"
}

// extractScanParams extracts common scan parameters from the policy
func (r *ImageResourcePolicyReconciler) extractScanParams(policy *automationv1beta1.ImageResourcePolicy) (pattern, patternType, region string, maxRepos int32, err error) {
	if policy.Spec.GenericRegistry != nil {
		if err = policy.Spec.GenericRegistry.Validate(); err != nil {
			return
		}
		pattern = policy.Spec.GenericRegistry.GetPattern()
		patternType = policy.Spec.GenericRegistry.GetPatternType()
		region = "" // not used for generic registry
		maxRepos = policy.Spec.GenericRegistry.MaxRepositories
	} else if policy.Spec.ECRRepository != nil {
		if err = policy.Spec.ECRRepository.Validate(); err != nil {
			return
		}
		pattern = policy.Spec.ECRRepository.GetPattern()
		patternType = policy.Spec.ECRRepository.GetPatternType()
		region = policy.Spec.ECRRepository.Region
		maxRepos = policy.Spec.ECRRepository.MaxRepositories
	} else {
		err = fmt.Errorf("exactly one of ecrRepository or genericRegistry must be specified")
		return
	}

	if maxRepos == 0 {
		maxRepos = 50
	}
	return
}

// createRegistryClient creates a registry client based on the policy configuration
func (r *ImageResourcePolicyReconciler) createRegistryClient(policy *automationv1beta1.ImageResourcePolicy) (registry.ImageRegistry, error) {
	if r.RegistryFactory == nil {
		r.RegistryFactory = registry.NewDefaultFactory()
	}

	if policy.Spec.GenericRegistry != nil {
		return r.createGenericRegistryClient(policy)
	}
	return r.createECRRegistryClient(policy)
}

// createGenericRegistryClient creates a generic registry client
func (r *ImageResourcePolicyReconciler) createGenericRegistryClient(policy *automationv1beta1.ImageResourcePolicy) (registry.ImageRegistry, error) {
	registryClient, err := r.RegistryFactory.CreateRegistry(registry.RegistryTypeGeneric)
	if err != nil {
		return nil, fmt.Errorf("failed to create generic registry client: %w", err)
	}

	// Set registry URL
	if adapter, ok := registryClient.(*registry.GenericRegistryAdapter); ok {
		adapter.SetRegistryURL(policy.Spec.GenericRegistry.RegistryURL)
	}

	// Configure authentication if secret is provided
	authConfig := registry.AuthConfig{
		Type: registry.RegistryTypeGeneric,
	}

	if policy.Spec.GenericRegistry.SecretRef != nil {
		ctx := context.TODO()
		secret := &corev1.Secret{}
		secretKey := types.NamespacedName{
			Name:      policy.Spec.GenericRegistry.SecretRef.Name,
			Namespace: policy.Namespace,
		}
		if err := r.Get(ctx, secretKey, secret); err != nil {
			return nil, fmt.Errorf("failed to get registry secret: %w", err)
		}
		if username, exists := secret.Data["username"]; exists {
			authConfig.Username = string(username)
		}
		if password, exists := secret.Data["password"]; exists {
			authConfig.Password = string(password)
		}
	}

	ctx := context.TODO()
	if err := registryClient.Authenticate(ctx, authConfig); err != nil {
		return nil, fmt.Errorf("failed to authenticate with registry: %w", err)
	}

	return registryClient, nil
}

// createECRRegistryClient creates an ECR registry client
func (r *ImageResourcePolicyReconciler) createECRRegistryClient(policy *automationv1beta1.ImageResourcePolicy) (registry.ImageRegistry, error) {
	registryClient, err := r.RegistryFactory.CreateRegistry(registry.RegistryTypeECR)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECR registry client: %w", err)
	}

	// Configure AWS authentication
	authConfig := registry.AuthConfig{
		Type: registry.RegistryTypeECR,
		AWSConfig: &registry.AWSAuthConfig{
			Region:                policy.Spec.ECRRepository.Region,
			UseDefaultCredentials: true,
		},
	}

	// Override with Secret-based authentication if specified
	if policy.Spec.AWS != nil && policy.Spec.AWS.SecretRef != nil {
		ctx := context.TODO()
		awsCredentials, err := r.getAWSCredentialsFromSecret(ctx, policy)
		if err != nil {
			return nil, fmt.Errorf("failed to get AWS credentials from secret: %w", err)
		}

		authConfig.AWSConfig = &registry.AWSAuthConfig{
			Region:                policy.Spec.ECRRepository.Region,
			AccessKeyID:           awsCredentials.AccessKeyID,
			SecretAccessKey:       awsCredentials.SecretAccessKey,
			SessionToken:          awsCredentials.SessionToken,
			UseDefaultCredentials: false,
		}
	}

	ctx := context.TODO()
	if err := registryClient.Authenticate(ctx, authConfig); err != nil {
		return nil, fmt.Errorf("failed to authenticate with ECR: %w", err)
	}

	return registryClient, nil
}

// applyPolicyFilter applies the image selection policy to filter images
func (r *ImageResourcePolicyReconciler) applyPolicyFilter(images []registry.ImageInfo, policySpec automationv1beta1.PolicySpec) []registry.ImageInfo {
	logger := log.FromContext(context.Background())

	// Initialize policy processor if not already done
	if r.PolicyProcessor == nil {
		r.PolicyProcessor = policy.NewPolicyProcessor()
	}

	// Validate policy first
	if err := r.PolicyProcessor.ValidatePolicy(policySpec); err != nil {
		logger.Error(err, "Invalid policy configuration, falling back to simple filtering")
		return r.fallbackFilter(images)
	}

	// Apply the policy
	filtered, err := r.PolicyProcessor.ApplyPolicy(images, policySpec)
	if err != nil {
		logger.Error(err, "Failed to apply policy, falling back to simple filtering")
		return r.fallbackFilter(images)
	}

	// Get policy statistics for logging
	stats := r.PolicyProcessor.GetPolicyStats(images, filtered, policySpec)
	logger.Info("Policy applied successfully",
		"policyType", stats.PolicyType,
		"policyDetails", stats.PolicyDetails,
		"totalImages", stats.TotalImages,
		"filteredImages", stats.FilteredImages)

	// If no images pass the filter, use fallback
	if len(filtered) == 0 {
		logger.Info("No images matched policy, using fallback filtering")
		return r.fallbackFilter(images)
	}

	return filtered
}

// fallbackFilter provides a simple fallback filtering when policy fails
func (r *ImageResourcePolicyReconciler) fallbackFilter(images []registry.ImageInfo) []registry.ImageInfo {
	var filtered []registry.ImageInfo

	// Simple filtering: exclude "latest" tag for now to demonstrate filtering
	for _, img := range images {
		if img.Tag != "latest" || len(images) == 1 { // Keep latest if it's the only image
			filtered = append(filtered, img)
		}
	}

	// If no images pass the filter, return the most recent one
	if len(filtered) == 0 && len(images) > 0 {
		filtered = []registry.ImageInfo{images[0]}
	}

	return filtered
}

// createImageDetectedIfNotExists creates an ImageDetected CRD if it doesn't already exist
func (r *ImageResourcePolicyReconciler) createImageDetectedIfNotExists(ctx context.Context, imagePolicy *automationv1beta1.ImageResourcePolicy, img registry.ImageInfo) (bool, error) {
	logger := log.FromContext(ctx)

	// Extract tag prefix if pattern policy with extractPrefix is enabled
	var tagPrefix string
	if imagePolicy.Spec.Policy.Pattern != nil && imagePolicy.Spec.Policy.Pattern.ExtractPrefix {
		logger.V(1).Info("Extracting tag prefix from pattern policy",
			"regex", imagePolicy.Spec.Policy.Pattern.Regex,
			"imageTag", img.Tag)

		// Initialize policy processor if not already done
		if r.PolicyProcessor == nil {
			r.PolicyProcessor = policy.NewPolicyProcessor()
		}

		// Apply pattern policy with prefix extraction to get the prefix
		singleImageList := []registry.ImageInfo{img}
		_, prefixMap, err := r.PolicyProcessor.ApplyPatternPolicyWithPrefix(singleImageList, *imagePolicy.Spec.Policy.Pattern)
		if err != nil {
			logger.Error(err, "Failed to extract prefix from tag, proceeding without prefix",
				"tag", img.Tag,
				"regex", imagePolicy.Spec.Policy.Pattern.Regex,
				"extractPrefix", imagePolicy.Spec.Policy.Pattern.ExtractPrefix)
			// Continue without prefix rather than failing completely
		} else if prefixMap != nil {
			if extractedPrefix, exists := prefixMap[img.Tag]; exists {
				tagPrefix = extractedPrefix
				logger.Info("Successfully extracted tag prefix",
					"imageTag", img.Tag,
					"extractedPrefix", tagPrefix,
					"regex", imagePolicy.Spec.Policy.Pattern.Regex)
			} else {
				logger.V(1).Info("No prefix extracted for tag",
					"imageTag", img.Tag,
					"reason", "Tag did not match regex or no capture groups")
			}
		} else {
			logger.V(1).Info("Prefix extraction returned nil map",
				"imageTag", img.Tag,
				"extractPrefix", imagePolicy.Spec.Policy.Pattern.ExtractPrefix)
		}
	}

	// Generate name for ImageDetected resource
	// Format: {image-name}-{tag-sanitized}-{digest-short}
	imageName := r.extractImageName(img.Name)
	tagSanitized := r.sanitizeForK8sName(img.Tag)
	digestShort := r.extractDigestShort(img.Digest)
	detectedName := fmt.Sprintf("%s-%s-%s", imageName, tagSanitized, digestShort)

	// Check if ImageDetected already exists
	existing := &automationv1beta1.ImageDetected{}
	namespacedName := types.NamespacedName{
		Name:      detectedName,
		Namespace: imagePolicy.Namespace,
	}

	err := r.Get(ctx, namespacedName, existing)
	if err == nil {
		// Already exists, skip creation
		logger.Info("ImageDetected already exists", "name", detectedName)
		return false, nil
	}
	if !errors.IsNotFound(err) {
		return false, fmt.Errorf("failed to check existing ImageDetected: %w", err)
	}

	// Create new ImageDetected
	imageDetected := &automationv1beta1.ImageDetected{
		ObjectMeta: metav1.ObjectMeta{
			Name:      detectedName,
			Namespace: imagePolicy.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "image-resource-controller",
				"app.kubernetes.io/component": "image-detected",
				"automation.gitops.io/source": imagePolicy.Name,
			},
			Annotations: map[string]string{
				"automation.gitops.io/source-policy": imagePolicy.Name,
			},
		},
		Spec: automationv1beta1.ImageDetectedSpec{
			ImageName:     imageName,
			ImageTag:      img.Tag,
			ImageDigest:   img.Digest,
			FullImageName: img.FullURL,
			TagPrefix:     tagPrefix, // New field with extracted prefix
			SourcePolicy: automationv1beta1.SourcePolicyRef{
				Name:      imagePolicy.Name,
				Namespace: imagePolicy.Namespace,
			},
			DetectedAt: func() metav1.Time {
				if img.PushedAt.IsZero() {
					return metav1.Now()
				}
				return metav1.Time{Time: img.PushedAt}
			}(),
		},
		Status: automationv1beta1.ImageDetectedStatus{
			Phase: "Pending",
		},
	}

	// ImageDetected is created with sourcePolicy reference only
	// Creation Controller will handle ResourceTemplate lookup via sourcePolicy

	if err := r.Create(ctx, imageDetected); err != nil {
		return false, fmt.Errorf("failed to create ImageDetected: %w", err)
	}

	logger.Info("Created ImageDetected",
		"name", detectedName,
		"image", img.Name,
		"tag", img.Tag,
		"tagPrefix", tagPrefix,
		"digest", digestShort)

	return true, nil
}

// updateStatusError updates status with error information
func (r *ImageResourcePolicyReconciler) updateStatusError(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy, message string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	policy.Status.ObservedGeneration = policy.Generation

	// Set error condition
	condition := metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonReconcileError,
		Message:            message,
	}
	r.setCondition(&policy.Status.Conditions, condition)

	if err := r.Status().Update(ctx, policy); err != nil {
		logger.Error(err, "Failed to update ImageResourcePolicy status with error")
		return ctrl.Result{RequeueAfter: ErrorRequeueInterval}, err
	}

	logger.Error(nil, "ECR scan failed", "message", message)
	// Requeue with error interval
	return ctrl.Result{RequeueAfter: ErrorRequeueInterval}, nil
}

// updateStatusScanSuccess updates status after successful scan
func (r *ImageResourcePolicyReconciler) updateStatusScanSuccess(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy, totalImages, createdImages int) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	policy.Status.ObservedGeneration = policy.Generation
	now := metav1.Now()
	policy.Status.LastScannedTime = &now

	// Remove any suspended conditions
	r.removeCondition(&policy.Status.Conditions, ConditionSuspended)

	// Set success condition
	message := fmt.Sprintf("Scanned %d images, created %d new ImageDetected resources", totalImages, createdImages)
	condition := metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonReconcileSuccess,
		Message:            message,
	}
	r.setCondition(&policy.Status.Conditions, condition)

	if err := r.Status().Update(ctx, policy); err != nil {
		logger.Error(err, "Failed to update ImageResourcePolicy status")
		return ctrl.Result{RequeueAfter: ErrorRequeueInterval}, err
	}

	logger.Info("ECR scan completed successfully",
		"totalImages", totalImages,
		"createdImages", createdImages)

	// Requeue after default interval
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// Helper functions
func (r *ImageResourcePolicyReconciler) extractImageName(fullName string) string {
	// Extract image name from repository name
	// For "namespace/service" -> "service"
	// For "service" -> "service"
	parts := strings.Split(fullName, "/")
	return parts[len(parts)-1]
}

func (r *ImageResourcePolicyReconciler) sanitizeForK8sName(name string) string {
	// Replace invalid characters for Kubernetes resource names
	sanitized := strings.ToLower(name)
	sanitized = strings.ReplaceAll(sanitized, ".", "-")
	sanitized = strings.ReplaceAll(sanitized, "_", "-")
	sanitized = strings.ReplaceAll(sanitized, "+", "-")

	// Ensure it doesn't start or end with hyphen
	sanitized = strings.Trim(sanitized, "-")

	// Limit length to reasonable size
	if len(sanitized) > 20 {
		sanitized = sanitized[:20]
	}

	return sanitized
}

func (r *ImageResourcePolicyReconciler) extractDigestShort(digest string) string {
	// Extract short version of digest for naming
	// "sha256:abc123..." -> "abc123"
	if strings.Contains(digest, ":") {
		parts := strings.Split(digest, ":")
		if len(parts) > 1 && len(parts[1]) > 8 {
			return parts[1][:8]
		}
	}
	// Fallback
	return "unknown"
}

// cleanupExpiredImageDetected removes ImageDetected resources that exceed the TTL
func (r *ImageResourcePolicyReconciler) cleanupExpiredImageDetected(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy) (int, error) {
	logger := log.FromContext(ctx)

	// Skip cleanup if TTLDays is 0 (disabled)
	if policy.Spec.TTLDays == 0 {
		return 0, nil
	}

	// List all ImageDetected resources created by this policy
	var imageDetectedList automationv1beta1.ImageDetectedList
	listOpts := []client.ListOption{
		client.InNamespace(policy.Namespace),
		client.MatchingLabels{"automation.gitops.io/source": policy.Name},
	}

	if err := r.List(ctx, &imageDetectedList, listOpts...); err != nil {
		return 0, fmt.Errorf("failed to list ImageDetected resources: %w", err)
	}

	// Calculate expiration cutoff time
	cutoffTime := time.Now().AddDate(0, 0, -int(policy.Spec.TTLDays))
	logger.Info("Cleaning up ImageDetected resources",
		"ttlDays", policy.Spec.TTLDays,
		"cutoffTime", cutoffTime.Format(time.RFC3339),
		"totalResources", len(imageDetectedList.Items))

	var cleanedCount int
	for _, imageDetected := range imageDetectedList.Items {
		// Check if resource is older than TTL
		if imageDetected.Spec.DetectedAt.Time.Before(cutoffTime) {
			logger.Info("Deleting expired ImageDetected resource",
				"name", imageDetected.Name,
				"detectedAt", imageDetected.Spec.DetectedAt.Time.Format(time.RFC3339),
				"age", time.Since(imageDetected.Spec.DetectedAt.Time).String())

			if err := r.Delete(ctx, &imageDetected); err != nil {
				if !errors.IsNotFound(err) {
					logger.Error(err, "Failed to delete expired ImageDetected resource", "name", imageDetected.Name)
					continue
				}
			}
			cleanedCount++
		}
	}

	return cleanedCount, nil
}

// processImagesPerRepository processes images on a per-repository basis
func (r *ImageResourcePolicyReconciler) processImagesPerRepository(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy, registryClient registry.ImageRegistry) (int, error) {
	logger := log.FromContext(ctx)

	pattern, patternType, region, maxRepos, err := r.extractScanParams(policy)
	if err != nil {
		return 0, fmt.Errorf("invalid configuration: %w", err)
	}

	logger.Info("Starting per-repository processing",
		"pattern", pattern,
		"patternType", patternType,
		"perRepository", true)

	var totalCreatedCount int

	// Determine registry type for ScanRepository config
	regType := registry.RegistryTypeECR
	var registryURL string
	if policy.Spec.GenericRegistry != nil {
		regType = registry.RegistryTypeGeneric
		registryURL = policy.Spec.GenericRegistry.RegistryURL
	}

	switch patternType {
	case patternTypeRepository:
		// Get list of matching repositories first
		repositories, err := registryClient.FindRepositoriesByPattern(ctx, region, pattern, maxRepos)
		if err != nil {
			return 0, fmt.Errorf("failed to find repositories by pattern: %w", err)
		}

		logger.Info("Found matching repositories", "count", len(repositories), "repositories", repositories)

		// Process each repository separately
		for _, repoName := range repositories {
			repoImages, err := registryClient.ScanRepository(ctx, registry.RegistryConfig{
				Type:           regType,
				RepositoryName: repoName,
				Region:         region,
				RegistryURL:    registryURL,
			})
			if err != nil {
				logger.Error(err, "Failed to scan repository", "repository", repoName)
				continue
			}

			if len(repoImages) == 0 {
				logger.Info("No images found in repository", "repository", repoName)
				continue
			}

			// Apply policy to this repository's images
			filteredImages := r.applyPolicyFilter(repoImages, policy.Spec.Policy)
			logger.Info("Images after policy filtering for repository",
				"repository", repoName,
				"totalImages", len(repoImages),
				"filteredImages", len(filteredImages))

			// Create ImageDetected resources for filtered images
			for _, img := range filteredImages {
				created, createErr := r.createImageDetectedIfNotExists(ctx, policy, img)
				if createErr != nil {
					logger.Error(createErr, "Failed to create ImageDetected",
						"repository", repoName,
						"image", img.Name,
						"tag", img.Tag)
					continue
				}
				if created {
					totalCreatedCount++
				}
			}
		}

	case "imageName", "image":
		return 0, fmt.Errorf("perRepository mode is not yet supported for patternType '%s', use 'repository' pattern type instead", patternType)

	default:
		return 0, fmt.Errorf("unknown pattern type '%s'", patternType)
	}

	var totalRepositories int
	if patternType == patternTypeRepository {
		if repositories, err := registryClient.FindRepositoriesByPattern(ctx, region, pattern, maxRepos); err == nil {
			totalRepositories = len(repositories)
		}
	}

	logger.Info("Completed per-repository processing",
		"totalRepositories", totalRepositories,
		"totalCreatedImageDetected", totalCreatedCount)

	return totalCreatedCount, nil
}

// AWSCredentials represents AWS authentication credentials from Secret
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// getAWSCredentialsFromSecret reads AWS credentials from Kubernetes Secret
func (r *ImageResourcePolicyReconciler) getAWSCredentialsFromSecret(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy) (*AWSCredentials, error) {
	logger := log.FromContext(ctx)

	if policy.Spec.AWS == nil || policy.Spec.AWS.SecretRef == nil {
		return nil, fmt.Errorf("AWS secret reference not specified")
	}

	secretName := policy.Spec.AWS.SecretRef.Name
	secretNamespace := policy.Namespace // Secret is in the same namespace as the policy

	// Get the Secret from Kubernetes
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}

	if err := r.Get(ctx, secretKey, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", secretNamespace, secretName, err)
	}

	// Extract credentials from Secret data
	credentials := &AWSCredentials{}

	// Access Key ID is required
	if accessKeyData, exists := secret.Data["accessKeyId"]; exists {
		credentials.AccessKeyID = string(accessKeyData)
	} else {
		return nil, fmt.Errorf("accessKeyId not found in secret %s", secretName)
	}

	// Secret Access Key is required
	if secretKeyData, exists := secret.Data["secretAccessKey"]; exists {
		credentials.SecretAccessKey = string(secretKeyData)
	} else {
		return nil, fmt.Errorf("secretAccessKey not found in secret %s", secretName)
	}

	// Session Token is optional
	if sessionTokenData, exists := secret.Data["sessionToken"]; exists {
		credentials.SessionToken = string(sessionTokenData)
	}

	logger.Info("Successfully read AWS credentials from secret",
		"secretName", secretName,
		"hasSessionToken", credentials.SessionToken != "")

	return credentials, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageResourcePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automationv1beta1.ImageResourcePolicy{}).
		Complete(r)
}
