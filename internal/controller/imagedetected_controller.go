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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	automationv1beta1 "github.com/S-mishina/image-resource-controller/api/v1beta1"
	"github.com/S-mishina/image-resource-controller/internal/git"
	"github.com/S-mishina/image-resource-controller/internal/k8s"
	"github.com/S-mishina/image-resource-controller/internal/template"
)

// ImageDetectedReconciler reconciles a ImageDetected object
type ImageDetectedReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Dependencies for resource creation
	ExistenceChecker  k8s.ExistenceChecker
	TemplateProcessor *template.Processor
}

// +kubebuilder:rbac:groups=automation.gitops.io,resources=imagedetecteds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automation.gitops.io,resources=imagedetecteds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automation.gitops.io,resources=imagedetecteds/finalizers,verbs=update
// +kubebuilder:rbac:groups=automation.gitops.io,resources=resourcetemplates,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs;cronjobs,verbs=get;list;watch

// Reconcile handles ImageDetected resources by creating Kubernetes manifests and committing to Git
func (r *ImageDetectedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("imagedetected", req.NamespacedName)

	// Fetch the ImageDetected resource
	var imageDetected automationv1beta1.ImageDetected
	if err := r.Get(ctx, req.NamespacedName, &imageDetected); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("ImageDetected resource not found, likely deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get ImageDetected resource")
		return ctrl.Result{}, err
	}

	logger.Info("Processing ImageDetected resource",
		"imageName", imageDetected.Spec.ImageName,
		"imageTag", imageDetected.Spec.ImageTag,
		"phase", imageDetected.Status.Phase)

	// Skip if already completed
	if imageDetected.Status.Phase == "Completed" {
		logger.Info("ImageDetected already completed, skipping")
		return ctrl.Result{}, nil
	}

	// Update phase to Processing
	if imageDetected.Status.Phase == "" || imageDetected.Status.Phase == "Pending" {
		if err := r.updatePhase(ctx, &imageDetected, "Processing", "Starting resource creation process"); err != nil {
			logger.Error(err, "Failed to update phase to Processing")
			return ctrl.Result{RequeueAfter: 30 * time.Second}, err
		}
	}

	// Check if image already exists in cluster with prefix-aware logic
	var exists bool
	var usage []k8s.ResourceInfo
	var err error

	if imageDetected.Spec.TagPrefix != "" {
		// Use prefix-aware existence check
		exists, usage, err = r.ExistenceChecker.CheckImageExistsWithTagPrefix(
			ctx,
			imageDetected.Spec.ImageName,
			imageDetected.Spec.TagPrefix,
		)

		logger.Info("Prefix-aware existence check",
			"imageName", imageDetected.Spec.ImageName,
			"tagPrefix", imageDetected.Spec.TagPrefix,
			"newTag", imageDetected.Spec.ImageTag)
	} else {
		// Use traditional existence check
		fullImageName := imageDetected.Spec.FullImageName // Already contains complete image URL with tag
		exists, usage, err = r.ExistenceChecker.CheckImageExists(ctx, fullImageName)
	}

	if err != nil {
		logger.Error(err, "Failed to check image existence")
		if updateErr := r.updatePhase(ctx, &imageDetected, "Failed", fmt.Sprintf("Failed to check image existence: %v", err)); updateErr != nil {
			logger.Error(updateErr, "Failed to update phase to Failed")
		}
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, err
	}

	if exists {
		var reason string
		if imageDetected.Spec.TagPrefix != "" {
			reason = "Same tag prefix pattern exists - delegating to Flux for version updates"
		} else {
			reason = "Duplicate resource creation prevented - image already deployed"
		}

		logger.Info("Image already exists in cluster, skipping resource creation and Git operations",
			"image", imageDetected.Spec.FullImageName,
			"imageName", imageDetected.Spec.ImageName,
			"imageTag", imageDetected.Spec.ImageTag,
			"tagPrefix", imageDetected.Spec.TagPrefix,
			"existingResourcesCount", len(usage),
			"reason", reason)

		// Log details about existing resources
		for _, resource := range usage {
			if imageDetected.Spec.TagPrefix != "" {
				// Extract tag from existing resource for prefix comparison
				existingTag := extractTagFromImage(resource.Image)
				logger.Info("Found existing resource with matching tag prefix",
					"resourceKind", resource.Kind,
					"resourceName", resource.Name,
					"resourceNamespace", resource.Namespace,
					"existingTag", existingTag,
					"containerName", resource.Container)
			} else {
				logger.Info("Found existing resource using this image",
					"resourceKind", resource.Kind,
					"resourceName", resource.Name,
					"resourceNamespace", resource.Namespace,
					"containerName", resource.Container)
			}
		}

		if err := r.updatePhase(ctx, &imageDetected, "Completed", reason); err != nil {
			logger.Error(err, "Failed to update phase to Completed")
			return ctrl.Result{RequeueAfter: 30 * time.Second}, err
		}
		return ctrl.Result{}, nil
	}

	// Get ImageResourcePolicy from sourcePolicy to fetch templateRef
	var imageResourcePolicy automationv1beta1.ImageResourcePolicy
	policyKey := client.ObjectKey{
		Name:      imageDetected.Spec.SourcePolicy.Name,
		Namespace: imageDetected.Spec.SourcePolicy.Namespace,
	}
	if policyKey.Namespace == "" {
		policyKey.Namespace = imageDetected.Namespace
	}

	if err := r.Get(ctx, policyKey, &imageResourcePolicy); err != nil {
		logger.Error(err, "Failed to get ImageResourcePolicy", "sourcePolicy", imageDetected.Spec.SourcePolicy)
		if updateErr := r.updatePhase(ctx, &imageDetected, "Failed", fmt.Sprintf("Failed to get ImageResourcePolicy: %v", err)); updateErr != nil {
			logger.Error(updateErr, "Failed to update phase to Failed")
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
	}

	// Fetch ResourceTemplate using templateRef from ImageResourcePolicy
	var resourceTemplate automationv1beta1.ResourceTemplate
	templateKey := client.ObjectKey{
		Name:      imageResourcePolicy.Spec.TemplateRef.Name,
		Namespace: imageResourcePolicy.Spec.TemplateRef.Namespace,
	}
	if templateKey.Namespace == "" {
		templateKey.Namespace = imageResourcePolicy.Namespace
	}

	if err := r.Get(ctx, templateKey, &resourceTemplate); err != nil {
		logger.Error(err, "Failed to get ResourceTemplate", "templateRef", imageResourcePolicy.Spec.TemplateRef)
		if updateErr := r.updatePhase(ctx, &imageDetected, "Failed", fmt.Sprintf("Failed to get ResourceTemplate: %v", err)); updateErr != nil {
			logger.Error(updateErr, "Failed to update phase to Failed")
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
	}

	// Process template to generate Kubernetes manifests
	manifests, err := r.processTemplate(ctx, &imageDetected, &resourceTemplate)
	if err != nil {
		logger.Error(err, "Failed to process template")
		if updateErr := r.updatePhase(ctx, &imageDetected, "Failed", fmt.Sprintf("Failed to process template: %v", err)); updateErr != nil {
			logger.Error(updateErr, "Failed to update phase to Failed")
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
	}

	// Commit manifests to Git repository
	commitSHA, err := r.commitToGit(ctx, &imageDetected, &resourceTemplate, manifests)
	if err != nil {
		logger.Error(err, "Failed to commit to Git")
		if updateErr := r.updatePhase(ctx, &imageDetected, "Failed", fmt.Sprintf("Failed to commit to Git: %v", err)); updateErr != nil {
			logger.Error(updateErr, "Failed to update phase to Failed")
		}

		// Determine retry interval based on error type
		retryInterval := r.determineRetryInterval(err)
		logger.Info("Git operation failed, will retry later", "retryAfter", retryInterval, "error", err.Error())
		return ctrl.Result{RequeueAfter: retryInterval}, nil // Return nil to prevent exponential backoff
	}

	// Update status to Completed
	now := metav1.Now()
	imageDetected.Status.ResourceCreated = true
	imageDetected.Status.GitCommitSHA = commitSHA
	imageDetected.Status.ProcessedAt = &now

	if err := r.updatePhase(ctx, &imageDetected, "Completed", "Successfully created resources and committed to Git"); err != nil {
		logger.Error(err, "Failed to update phase to Completed")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	logger.Info("Successfully processed ImageDetected resource",
		"commitSHA", commitSHA,
		"manifestsGenerated", len(manifests))

	return ctrl.Result{}, nil
}

// updatePhase updates the ImageDetected phase and condition
func (r *ImageDetectedReconciler) updatePhase(ctx context.Context, imageDetected *automationv1beta1.ImageDetected, phase, message string) error {
	imageDetected.Status.Phase = phase

	// Add or update condition
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               "Processing",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             phase,
		Message:            message,
	}

	if phase == "Failed" {
		condition.Status = metav1.ConditionFalse
	} else if phase == "Completed" {
		condition.Type = "Ready"
	}

	// Update or append condition
	found := false
	for i, cond := range imageDetected.Status.Conditions {
		if cond.Type == condition.Type {
			imageDetected.Status.Conditions[i] = condition
			found = true
			break
		}
	}
	if !found {
		imageDetected.Status.Conditions = append(imageDetected.Status.Conditions, condition)
	}

	return r.Status().Update(ctx, imageDetected)
}

// processTemplate generates Kubernetes manifests from the template
func (r *ImageDetectedReconciler) processTemplate(ctx context.Context, imageDetected *automationv1beta1.ImageDetected, resourceTemplate *automationv1beta1.ResourceTemplate) (map[string]string, error) {
	logger := log.FromContext(ctx)

	var vars template.TemplateVars
	var err error

	// Use BuildTemplateVarsWithPrefix if TagPrefix is present
	if imageDetected.Spec.TagPrefix != "" {
		vars, err = r.TemplateProcessor.BuildTemplateVarsWithPrefix(
			imageDetected.Spec.FullImageName,
			imageDetected.Spec.ImageTag,
			imageDetected.Spec.ImageDigest,
			imageDetected.Spec.TagPrefix,
			resourceTemplate.Spec.Variables, // Additional variables from ResourceTemplate
		)
	} else {
		vars, err = r.TemplateProcessor.BuildTemplateVars(
			imageDetected.Spec.FullImageName,
			imageDetected.Spec.ImageTag,
			imageDetected.Spec.ImageDigest,
			resourceTemplate.Spec.Variables, // Additional variables from ResourceTemplate
		)
	}

	if err != nil {
		logger.Error(err, "Failed to build template variables", "fullImageName", imageDetected.Spec.FullImageName)
		// Use basic variables as fallback
		vars = template.TemplateVars{
			ImageTag:      imageDetected.Spec.ImageTag,
			ImageDigest:   imageDetected.Spec.ImageDigest,
			FullImageName: imageDetected.Spec.FullImageName,
			ServiceName:   imageDetected.Spec.ImageName,
			TagPrefix:     imageDetected.Spec.TagPrefix,
			Variables:     resourceTemplate.Spec.Variables,
		}
	}

	// Check if multiFiles is specified (new feature)
	if len(resourceTemplate.Spec.MultiFiles) > 0 {
		logger.Info("Using multi-file template generation", "filesCount", len(resourceTemplate.Spec.MultiFiles))
		return r.processMultiFileTemplate(ctx, resourceTemplate, vars)
	}

	// Legacy single-file processing (backward compatibility)
	logger.Info("Using legacy single-file template generation")
	return r.processSingleFileTemplate(ctx, imageDetected, resourceTemplate, vars)
}

// processMultiFileTemplate processes multiple file templates
func (r *ImageDetectedReconciler) processMultiFileTemplate(ctx context.Context, resourceTemplate *automationv1beta1.ResourceTemplate, vars template.TemplateVars) (map[string]string, error) {
	logger := log.FromContext(ctx)
	basePath := resourceTemplate.Spec.GitRepository.Path
	manifests := make(map[string]string)

	for _, fileTemplate := range resourceTemplate.Spec.MultiFiles {
		// Process relative path template
		renderedRelativePath, err := r.TemplateProcessor.ProcessPathTemplate(fileTemplate.RelativePath, vars)
		if err != nil {
			return nil, fmt.Errorf("failed to render relative path for file template '%s': %w", fileTemplate.Name, err)
		}

		// Construct final path (basePath + relativePath)
		finalPath := fmt.Sprintf("%s/%s", strings.TrimRight(basePath, "/"), strings.TrimLeft(renderedRelativePath, "/"))

		// Process template content
		content, err := r.TemplateProcessor.ProcessTemplateString(fileTemplate.Template, vars)
		if err != nil {
			return nil, fmt.Errorf("failed to process template content for file template '%s': %w", fileTemplate.Name, err)
		}

		manifests[finalPath] = content

		logger.Info("Generated file from multi-file template",
			"templateName", fileTemplate.Name,
			"relativePath", renderedRelativePath,
			"finalPath", finalPath,
			"contentSize", len(content))
	}

	logger.Info("Multi-file template processing completed",
		"totalFiles", len(manifests),
		"templateVars", vars)

	return manifests, nil
}

// processSingleFileTemplate processes single template (legacy mode)
func (r *ImageDetectedReconciler) processSingleFileTemplate(ctx context.Context, imageDetected *automationv1beta1.ImageDetected, resourceTemplate *automationv1beta1.ResourceTemplate, vars template.TemplateVars) (map[string]string, error) {
	logger := log.FromContext(ctx)

	// Ensure template field exists for backward compatibility
	if resourceTemplate.Spec.Template == "" {
		return nil, fmt.Errorf("template field is required when multiFiles is not specified")
	}

	// Process template
	result, err := r.TemplateProcessor.ProcessTemplate(resourceTemplate.Spec.Template, vars)
	if err != nil {
		return nil, fmt.Errorf("failed to process single template: %w", err)
	}

	// Generate file name from image name and prefix to avoid conflicts
	var fileName string
	if imageDetected.Spec.TagPrefix != "" {
		// Include prefix in filename to avoid conflicts between environments
		fileName = fmt.Sprintf("%s-%s.yaml", imageDetected.Spec.ImageName, imageDetected.Spec.TagPrefix)
	} else {
		fileName = fmt.Sprintf("%s.yaml", imageDetected.Spec.ImageName)
	}

	manifests := map[string]string{
		fileName: string(result),
	}

	logger.Info("Generated manifest from single template",
		"fileName", fileName,
		"templateVars", vars,
		"contentSize", len(result))

	return manifests, nil
}

// commitToGit commits the generated manifests to the Git repository
func (r *ImageDetectedReconciler) commitToGit(ctx context.Context, imageDetected *automationv1beta1.ImageDetected, resourceTemplate *automationv1beta1.ResourceTemplate, manifests map[string]string) (string, error) {
	logger := log.FromContext(ctx)

	// Extract Git configuration from ResourceTemplate
	gitRepo := resourceTemplate.Spec.GitRepository

	// Create Git auth config
	authConfig := git.AuthConfig{
		Type: git.AuthTypeGitHubToken, // Default to GitHub token
	}

	// Get auth secret if specified
	if gitRepo.SecretRef != nil {
		secret := &corev1.Secret{}
		secretKey := client.ObjectKey{
			Name:      gitRepo.SecretRef.Name,
			Namespace: imageDetected.Namespace,
		}

		if err := r.Get(ctx, secretKey, secret); err != nil {
			return "", fmt.Errorf("failed to get Git secret: %w", err)
		}

		// Configure auth based on secret data
		if token, exists := secret.Data["token"]; exists {
			authConfig.Token = string(token)
		} else if username, exists := secret.Data["username"]; exists {
			authConfig.Type = git.AuthTypeHTTP
			authConfig.Username = string(username)
			if password, exists := secret.Data["password"]; exists {
				authConfig.Password = string(password)
			}
		} else if privateKey, exists := secret.Data["ssh-privatekey"]; exists {
			authConfig.Type = git.AuthTypeSSH
			authConfig.SSHPrivateKey = privateKey
			if passphrase, exists := secret.Data["ssh-passphrase"]; exists {
				authConfig.SSHPassphrase = string(passphrase)
			}
		}
	}

	// Create Git operations instance
	gitOps := git.NewOperations("", authConfig)
	gitOps.SetAuthor("Image Resource Controller", "image-controller@example.com")

	// Generate commit message
	commitMessage := git.GenerateCommitMessage(
		imageDetected.Spec.ImageName,
		imageDetected.Spec.ImageTag,
		"create",
	)

	// Execute Git operation
	result, err := gitOps.CloneAndCommitFiles(
		ctx,
		gitRepo.URL,
		gitRepo.Branch,
		manifests,
		commitMessage,
	)

	if err != nil {
		return "", fmt.Errorf("failed to execute Git operation: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("Git operation failed: %s", result.Error)
	}

	logger.Info("Successfully committed manifests to Git",
		"commitSHA", result.CommitInfo.Hash,
		"filesChanged", result.FilesChanged,
		"repoURL", gitRepo.URL,
		"branch", gitRepo.Branch)

	return result.CommitInfo.Hash, nil
}

// determineRetryInterval determines the retry interval based on error type
func (r *ImageDetectedReconciler) determineRetryInterval(err error) time.Duration {
	errorString := err.Error()

	// Git authentication errors - these are configuration issues, retry slowly
	if strings.Contains(errorString, "authentication") ||
		strings.Contains(errorString, "username and password") ||
		strings.Contains(errorString, "token") ||
		strings.Contains(errorString, "permission denied") {
		return 30 * time.Minute // Long interval for auth issues
	}

	// Network/connection errors - temporary issues, medium retry
	if strings.Contains(errorString, "connection") ||
		strings.Contains(errorString, "network") ||
		strings.Contains(errorString, "timeout") ||
		strings.Contains(errorString, "dial") {
		return 5 * time.Minute
	}

	// Resource not found errors - configuration issues
	if strings.Contains(errorString, "not found") ||
		strings.Contains(errorString, "does not exist") {
		return 15 * time.Minute
	}

	// Template processing errors - configuration issues
	if strings.Contains(errorString, "template") ||
		strings.Contains(errorString, "parse") {
		return 10 * time.Minute
	}

	// Default retry interval for unknown errors
	return 5 * time.Minute
}

// extractTagFromImage extracts tag from full image name
func extractTagFromImage(fullImageName string) string {
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

// SetupWithManager sets up the controller with the Manager.
func (r *ImageDetectedReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automationv1beta1.ImageDetected{}).
		Complete(r)
}
