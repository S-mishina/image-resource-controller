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
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestImageUsageCache(t *testing.T) {
	cache := NewImageUsageCache(1 * time.Second)

	// Test initial state
	if !cache.IsExpired() {
		t.Error("Cache should be expired initially")
	}

	// Test cache update
	testData := map[string][]ResourceInfo{
		"nginx": {
			{Namespace: "default", Name: "nginx-deployment", Kind: "Deployment", Image: "nginx:latest"},
		},
		"redis": {
			{Namespace: "default", Name: "redis-deployment", Kind: "Deployment", Image: "redis:6.0"},
		},
	}

	cache.UpdateCache(testData)

	// Test cache not expired immediately after update
	if cache.IsExpired() {
		t.Error("Cache should not be expired immediately after update")
	}

	// Test getting usage
	nginxUsage := cache.GetImageUsage("nginx")
	if len(nginxUsage) != 1 {
		t.Errorf("Expected 1 nginx usage, got %d", len(nginxUsage))
	}

	nonExistentUsage := cache.GetImageUsage("nonexistent")
	if len(nonExistentUsage) != 0 {
		t.Errorf("Expected 0 usage for nonexistent image, got %d", len(nonExistentUsage))
	}

	// Test cache expiration
	time.Sleep(1100 * time.Millisecond)
	if !cache.IsExpired() {
		t.Error("Cache should be expired after TTL")
	}

	// Test cache stats
	stats := cache.GetCacheStats()
	if stats.TotalImages != 2 {
		t.Errorf("Expected 2 total images, got %d", stats.TotalImages)
	}
	if stats.TotalResources != 2 {
		t.Errorf("Expected 2 total resources, got %d", stats.TotalResources)
	}
}

func TestExtractImageName(t *testing.T) {
	ec := &ExistenceChecker{}

	tests := []struct {
		input    string
		expected string
	}{
		{"nginx:latest", "nginx"},
		{"nginx", "nginx"},
		{"registry.example.com/nginx:latest", "nginx"},
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3", "my-service"},
		{"registry.example.com/namespace/service:v1.0.0", "service"},
		{"nginx:1.21@sha256:abc123", "nginx"},
		{"", ""},
	}

	for _, test := range tests {
		result := ec.extractImageName(test.input)
		if result != test.expected {
			t.Errorf("extractImageName(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestExistenceChecker(t *testing.T) {
	// Create fake Kubernetes client with test objects
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)

	// Create test objects
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-deployment",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:latest",
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:  "init-nginx",
							Image: "busybox:latest",
						},
					},
				},
			},
		},
	}

	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "redis-statefulset",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "redis",
							Image: "redis:6.0",
						},
					},
				},
			},
		},
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backup-job",
			Namespace: "default",
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "backup",
							Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-service:v1.2.3",
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(deployment, statefulSet, job).
		Build()

	ec := NewExistenceChecker(fakeClient, scheme)
	ctx := context.TODO()

	// Test image existence check
	t.Run("CheckImageExists", func(t *testing.T) {
		// Test existing image
		exists, usage, err := ec.CheckImageExists(ctx, "nginx")
		if err != nil {
			t.Fatalf("CheckImageExists failed: %v", err)
		}
		if !exists {
			t.Error("nginx should exist")
		}
		if len(usage) != 1 {
			t.Errorf("Expected 1 nginx usage, got %d", len(usage))
		}
		if usage[0].Kind != "Deployment" {
			t.Errorf("Expected Deployment, got %s", usage[0].Kind)
		}

		// Test ECR image
		exists, usage, err = ec.CheckImageExists(ctx, "my-service")
		if err != nil {
			t.Fatalf("CheckImageExists failed for ECR image: %v", err)
		}
		if !exists {
			t.Error("my-service should exist")
		}
		if len(usage) != 1 {
			t.Errorf("Expected 1 my-service usage, got %d", len(usage))
		}
		if usage[0].Kind != "Job" {
			t.Errorf("Expected Job, got %s", usage[0].Kind)
		}

		// Test non-existing image
		exists, usage, err = ec.CheckImageExists(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("CheckImageExists failed for nonexistent image: %v", err)
		}
		if exists {
			t.Error("nonexistent image should not exist")
		}
		if len(usage) != 0 {
			t.Errorf("Expected 0 usage for nonexistent image, got %d", len(usage))
		}
	})

	t.Run("CacheStats", func(t *testing.T) {
		// Force cache refresh to populate it
		err := ec.ForceRefresh(ctx)
		if err != nil {
			t.Fatalf("ForceRefresh failed: %v", err)
		}

		stats := ec.GetCacheStats()
		if stats.TotalImages < 3 { // Should have at least nginx, redis, busybox, my-service
			t.Errorf("Expected at least 3 images, got %d", stats.TotalImages)
		}
		if stats.TotalResources < 3 { // Should have at least deployment, statefulset, job
			t.Errorf("Expected at least 3 resources, got %d", stats.TotalResources)
		}
	})

	t.Run("InitContainerHandling", func(t *testing.T) {
		// Force cache refresh
		err := ec.ForceRefresh(ctx)
		if err != nil {
			t.Fatalf("ForceRefresh failed: %v", err)
		}

		// Check if init container image is detected
		exists, usage, err := ec.CheckImageExists(ctx, "busybox")
		if err != nil {
			t.Fatalf("CheckImageExists failed for busybox: %v", err)
		}
		if !exists {
			t.Error("busybox (init container) should exist")
		}
		if len(usage) != 1 {
			t.Errorf("Expected 1 busybox usage, got %d", len(usage))
		}
	})
}

func TestExistenceCheckerWithEmptyCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	ec := NewExistenceChecker(fakeClient, scheme)
	ctx := context.TODO()

	// Test with empty cluster
	exists, usage, err := ec.CheckImageExists(ctx, "nginx")
	if err != nil {
		t.Fatalf("CheckImageExists failed: %v", err)
	}
	if exists {
		t.Error("nginx should not exist in empty cluster")
	}
	if len(usage) != 0 {
		t.Errorf("Expected 0 usage, got %d", len(usage))
	}

	// Test cache stats with empty cluster
	stats := ec.GetCacheStats()
	if stats.TotalImages != 0 {
		t.Errorf("Expected 0 images in empty cluster, got %d", stats.TotalImages)
	}
	if stats.TotalResources != 0 {
		t.Errorf("Expected 0 resources in empty cluster, got %d", stats.TotalResources)
	}
}
