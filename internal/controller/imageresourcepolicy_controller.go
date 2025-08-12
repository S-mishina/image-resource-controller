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
	// Condition types
	ConditionReady     = "Ready"
	ConditionSuspended = "Suspended"

	// Condition reasons
	ReasonSuspended        = "Suspended"
	ReasonReconciling      = "Reconciling"
	ReasonReconcileSuccess = "ReconcileSuccess"
	ReasonReconcileError   = "ReconcileError"

	// Default requeue intervals
	DefaultRequeueInterval   = 5 * time.Minute
	SuspendedRequeueInterval = 30 * time.Minute
	ErrorRequeueInterval     = 2 * time.Minute
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
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ImageResourcePolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
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
		"repository", policy.Spec.ECRRepository.RepositoryName,
		"region", policy.Spec.ECRRepository.Region,
		"generation", policy.Generation)

	// 2. Check if the policy is suspended
	if policy.Spec.Suspend {
		logger.Info("ImageResourcePolicy is suspended, skipping ECR scan")
		return r.updateStatusSuspended(ctx, &policy)
	}

	// 3. Execute ECR scanning logic
	return r.executeECRScan(ctx, &policy)
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

// updateStatusReconciling updates status during normal reconciliation
func (r *ImageResourcePolicyReconciler) updateStatusReconciling(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Update ObservedGeneration
	policy.Status.ObservedGeneration = policy.Generation

	// Update LastScannedTime (even though we're not actually scanning yet)
	now := metav1.Now()
	policy.Status.LastScannedTime = &now

	// Remove Suspended condition if it exists
	r.removeCondition(&policy.Status.Conditions, ConditionSuspended)

	// Set Ready condition to True (for now, will change when we implement actual logic)
	condition := metav1.Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonReconciling,
		Message:            "ImageResourcePolicy is being processed (ECR scanning not yet implemented)",
	}
	r.setCondition(&policy.Status.Conditions, condition)

	if err := r.Status().Update(ctx, policy); err != nil {
		logger.Error(err, "Failed to update ImageResourcePolicy status")
		return ctrl.Result{RequeueAfter: ErrorRequeueInterval}, err
	}

	logger.Info("ImageResourcePolicy status updated", "state", "reconciling")
	// Requeue after default interval
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
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

// executeECRScan performs the actual ECR scanning and ImageDetected creation
func (r *ImageResourcePolicyReconciler) executeECRScan(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	logger.Info("Starting ECR scan", "repository", policy.Spec.ECRRepository.RepositoryName)

	// 1. Create registry client
	registryClient, err := r.createRegistryClient(policy)
	if err != nil {
		return r.updateStatusError(ctx, policy, fmt.Sprintf("Failed to create registry client: %v", err))
	}

	// 2. Scan repository for images
	config := registry.RegistryConfig{
		Type:           registry.RegistryTypeECR,
		RepositoryName: policy.Spec.ECRRepository.RepositoryName,
		Region:         policy.Spec.ECRRepository.Region,
	}

	images, err := registryClient.ScanRepository(ctx, config)
	if err != nil {
		return r.updateStatusError(ctx, policy, fmt.Sprintf("Failed to scan repository: %v", err))
	}

	logger.Info("Found images in repository", "count", len(images), "repository", policy.Spec.ECRRepository.RepositoryName)

	// 3. Apply policy filtering (simple implementation for now)
	// TODO: Implement actual policy processing (semver, pattern, alphabetical)
	filteredImages := r.applyPolicyFilter(images, policy.Spec.Policy)

	logger.Info("Images after policy filtering", "count", len(filteredImages))

	// 4. Check for duplicates and create ImageDetected CRDs
	createdCount := 0
	for _, img := range filteredImages {
		created, err := r.createImageDetectedIfNotExists(ctx, policy, img)
		if err != nil {
			logger.Error(err, "Failed to create ImageDetected", "image", img.Name, "tag", img.Tag)
			// Continue with other images instead of failing completely
			continue
		}
		if created {
			createdCount++
		}
	}

	// 5. Update status with scan results
	return r.updateStatusScanSuccess(ctx, policy, len(images), createdCount)
}

// createRegistryClient creates a registry client based on the policy configuration
func (r *ImageResourcePolicyReconciler) createRegistryClient(policy *automationv1beta1.ImageResourcePolicy) (registry.ImageRegistry, error) {
	if r.RegistryFactory == nil {
		r.RegistryFactory = registry.NewDefaultFactory()
	}

	registryClient, err := r.RegistryFactory.CreateRegistry(registry.RegistryTypeECR)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECR registry client: %w", err)
	}

	// TODO: Implement authentication configuration
	// authConfig := registry.AuthConfig{
	//     Type: registry.RegistryTypeECR,
	//     // Configure AWS auth based on policy.Spec.AWS
	// }
	// if err := registryClient.Authenticate(ctx, authConfig); err != nil {
	//     return nil, fmt.Errorf("failed to authenticate with ECR: %w", err)
	// }

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
func (r *ImageResourcePolicyReconciler) createImageDetectedIfNotExists(ctx context.Context, policy *automationv1beta1.ImageResourcePolicy, img registry.ImageInfo) (bool, error) {
	logger := log.FromContext(ctx)

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
		Namespace: policy.Namespace,
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
			Namespace: policy.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "image-resource-controller",
				"app.kubernetes.io/component": "image-detected",
				"automation.gitops.io/source": policy.Name,
			},
			Annotations: map[string]string{
				"automation.gitops.io/source-policy": policy.Name,
			},
		},
		Spec: automationv1beta1.ImageDetectedSpec{
			ImageName:     imageName,
			ImageTag:      img.Tag,
			ImageDigest:   img.Digest,
			FullImageName: img.FullURL,
			SourcePolicy: automationv1beta1.SourcePolicyRef{
				Name:      policy.Name,
				Namespace: policy.Namespace,
			},
			DetectedAt: metav1.Time{Time: img.PushedAt},
		},
		Status: automationv1beta1.ImageDetectedStatus{
			Phase: "Pending",
		},
	}

	if err := r.Create(ctx, imageDetected); err != nil {
		return false, fmt.Errorf("failed to create ImageDetected: %w", err)
	}

	logger.Info("Created ImageDetected",
		"name", detectedName,
		"image", img.Name,
		"tag", img.Tag,
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

// SetupWithManager sets up the controller with the Manager.
func (r *ImageResourcePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automationv1beta1.ImageResourcePolicy{}).
		Complete(r)
}
