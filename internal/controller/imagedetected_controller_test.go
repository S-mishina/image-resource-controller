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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	automationv1beta1 "github.com/S-mishina/image-resource-controller/api/v1beta1"
)

var _ = Describe("ImageDetected Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // NOTE: Using default namespace for tests
		}
		imagedetected := &automationv1beta1.ImageDetected{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind ImageDetected")
			err := k8sClient.Get(ctx, typeNamespacedName, imagedetected)
			if err != nil && errors.IsNotFound(err) {
				resource := &automationv1beta1.ImageDetected{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: automationv1beta1.ImageDetectedSpec{
						ImageName:     "test-app",
						ImageTag:      "v1.0.0",
						ImageDigest:   "sha256:abc123def456",
						FullImageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app",
						SourcePolicy: automationv1beta1.SourcePolicyRef{
							Name:      "test-policy",
							Namespace: "default",
						},
						DetectedAt: metav1.Now(),
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// NOTE: Cleanup logic to remove the resource instance after each test
			resource := &automationv1beta1.ImageDetected{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance ImageDetected")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			// Skip reconcile test for now as it requires additional dependencies
			// (ExistenceChecker, TemplateProcessor) and external services
			Skip("Skipping reconcile test - requires mocked dependencies")
		})
	})
})
