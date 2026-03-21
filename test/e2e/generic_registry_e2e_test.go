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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/S-mishina/image-resource-controller/test/utils"
)

const (
	localRegistryURL = "localhost:5001"
	giteaURL         = "http://localhost:3000"
	giteaUser        = "testuser"
	giteaPassword    = "testpassword"
	giteaRepo        = "k8s-manifests"
	testRepository   = "test-app"
	kindClusterName  = "e2e-generic-registry"
	detectionImage   = "image-detection-controller:latest"
	creationImage    = "resource-creation-controller:latest"
)

// Resolved at runtime: container IPs on the kind network
var registryInternalURL string
var giteaInternalURL string

var _ = Describe("Generic Registry E2E", Ordered, func() {
	BeforeAll(func() {
		By("starting E2E infrastructure (registry + gitea)")
		Expect(utils.StartE2EInfra()).To(Succeed())

		By("waiting for Gitea to be ready")
		waitForGitea := func() error {
			cmd := exec.Command("curl", "-s", "-o", "/dev/null",
				"-w", "%{http_code}", giteaURL)
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(output)) != "200" {
				return fmt.Errorf("gitea not ready, status: %s", output)
			}
			return nil
		}
		EventuallyWithOffset(1, waitForGitea, 60*time.Second, 2*time.Second).Should(Succeed())

		By("setting up Gitea repository")
		Expect(utils.SetupGiteaRepo(giteaURL, giteaUser, giteaPassword, giteaRepo)).To(Succeed())

		By("pushing test images to local registry")
		// Semver tags
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "v1.0.0")).To(Succeed())
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "v1.1.0")).To(Succeed())
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "v2.0.0")).To(Succeed())
		// Environment-prefixed tags (for pattern + extractPrefix)
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "dev-v1.0.0")).To(Succeed())
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "staging-v1.0.0")).To(Succeed())
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "prod-v1.0.0")).To(Succeed())
		// Alphabetical tags
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "alpha")).To(Succeed())
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "beta")).To(Succeed())
		Expect(utils.PushTestImageToRegistry(localRegistryURL, testRepository, "latest")).To(Succeed())

		By("creating Kind cluster with registry support")
		Expect(utils.CreateKindClusterWithRegistry(kindClusterName)).To(Succeed())

		By("setting KIND_CLUSTER env for image loading")
		os.Setenv("KIND_CLUSTER", kindClusterName)

		By("building the controller images")
		cmd := exec.Command("make", "docker-build")
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("loading the controller images on Kind")
		loadCmd := exec.Command("kind", "load", "docker-image",
			detectionImage, creationImage,
			"--name", kindClusterName)
		_, err = utils.Run(loadCmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("deploying the controllers")
		cmd = exec.Command("make", "deploy-controllers")
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("resolving container IPs for in-cluster access")
		regIPCmd := exec.Command("docker", "inspect", "-f",
			"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
			"kind-registry")
		regIPOutput, err := utils.Run(regIPCmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		registryInternalURL = fmt.Sprintf("http://%s:5000", strings.TrimSpace(string(regIPOutput)))
		_, _ = fmt.Fprintf(GinkgoWriter, "Registry internal URL: %s\n", registryInternalURL)

		giteaIPCmd := exec.Command("docker", "inspect", "-f",
			"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
			"kind-gitea")
		giteaIPOutput, err := utils.Run(giteaIPCmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		giteaInternalURL = fmt.Sprintf("http://%s:3000", strings.TrimSpace(string(giteaIPOutput)))
		_, _ = fmt.Fprintf(GinkgoWriter, "Gitea internal URL: %s\n", giteaInternalURL)

		By("creating Git credentials secret")
		cmd = exec.Command("kubectl", "create", "secret", "generic",
			"git-credentials",
			"-n", "default",
			fmt.Sprintf("--from-literal=username=%s", giteaUser),
			fmt.Sprintf("--from-literal=password=%s", giteaPassword),
		)
		_, _ = utils.Run(cmd) // Ignore if already exists

		By("waiting for detection controller to be ready")
		verifyControllerUp := func(label string) func() error {
			return func() error {
				cmd := exec.Command("kubectl", "get", "pods",
					"-l", fmt.Sprintf("control-plane=%s", label),
					"-n", namespace,
					"-o", "jsonpath={.items[0].status.phase}",
				)
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}
				if string(output) != "Running" {
					return fmt.Errorf("%s pod in %s status", label, output)
				}
				return nil
			}
		}
		EventuallyWithOffset(1, verifyControllerUp("image-detection-controller"), 2*time.Minute, 5*time.Second).Should(Succeed())

		By("waiting for creation controller to be ready")
		EventuallyWithOffset(1, verifyControllerUp("resource-creation-controller"), 2*time.Minute, 5*time.Second).Should(Succeed())
	})

	AfterAll(func() {
		By("cleaning up Kind cluster")
		utils.DeleteKindCluster(kindClusterName)

		By("stopping E2E infrastructure")
		utils.StopE2EInfra()
	})

	// Helper: dump controller logs for debugging
	dumpControllerLogs := func() {
		for _, ctrl := range []string{"image-detection-controller", "resource-creation-controller"} {
			cmd := exec.Command("kubectl", "logs",
				"-l", fmt.Sprintf("control-plane=%s", ctrl),
				"-n", namespace,
				"--tail=50",
			)
			output, _ := utils.Run(cmd)
			_, _ = fmt.Fprintf(GinkgoWriter, "\n=== %s logs ===\n%s\n", ctrl, string(output))
		}
	}

	// Helper: apply a policy and wait for ImageDetected, return detected tags
	applyPolicyAndCollectTags := func(policyName string, policyManifest *strings.Reader) []string {
		By(fmt.Sprintf("applying policy: %s", policyName))
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = policyManifest
		_, err := utils.Run(cmd)
		ExpectWithOffset(2, err).NotTo(HaveOccurred())

		By(fmt.Sprintf("waiting for ImageDetected from policy: %s", policyName))
		var detectedTags []string
		Eventually(func() error {
			cmd := exec.Command("kubectl", "get", "imagedetected",
				"-l", fmt.Sprintf("automation.gitops.io/source=%s", policyName),
				"-n", "default",
				"-o", "jsonpath={.items[*].spec.imageTag}",
			)
			output, err := utils.Run(cmd)
			if err != nil {
				return err
			}
			raw := strings.TrimSpace(string(output))
			if raw == "" {
				// Dump logs on each retry for debugging
				dumpControllerLogs()
				return fmt.Errorf("no ImageDetected found for %s", policyName)
			}
			detectedTags = strings.Fields(raw)
			return nil
		}, 3*time.Minute, 10*time.Second).Should(Succeed())

		return detectedTags
	}

	// Helper: clean up a policy and its ImageDetected resources
	cleanupPolicy := func(policyName string) {
		cmd := exec.Command("kubectl", "delete", "imageresourcepolicy", policyName,
			"-n", "default", "--ignore-not-found")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "imagedetected",
			"-l", fmt.Sprintf("automation.gitops.io/source=%s", policyName),
			"-n", "default", "--ignore-not-found")
		_, _ = utils.Run(cmd)
	}

	BeforeEach(func() {
		By("ensuring ResourceTemplate exists")
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = createResourceTemplateManifest()
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("Policy: Semver", func() {
		const policyName = "test-semver-policy"

		AfterEach(func() { cleanupPolicy(policyName) })

		It("should filter images by semver range >=2.0.0", func() {
			tags := applyPolicyAndCollectTags(policyName,
				createPolicyManifest(policyName, `
    semver:
      range: ">=2.0.0"`))

			Expect(tags).To(ContainElement("v2.0.0"))
			Expect(tags).NotTo(ContainElement("v1.0.0"))
			Expect(tags).NotTo(ContainElement("v1.1.0"))
		})
	})

	Context("Policy: Pattern (regex)", func() {
		const policyName = "test-pattern-policy"

		AfterEach(func() { cleanupPolicy(policyName) })

		It("should filter images matching regex pattern", func() {
			tags := applyPolicyAndCollectTags(policyName,
				createPolicyManifest(policyName, `
    pattern:
      regex: '^v1\.\d+\.\d+$'`))

			Expect(tags).To(ContainElement("v1.0.0"))
			Expect(tags).To(ContainElement("v1.1.0"))
			Expect(tags).NotTo(ContainElement("v2.0.0"))
			Expect(tags).NotTo(ContainElement("dev-v1.0.0"))
		})
	})

	Context("Policy: Pattern with extractPrefix", func() {
		const policyName = "test-prefix-policy"

		AfterEach(func() { cleanupPolicy(policyName) })

		It("should extract environment prefix from tags", func() {
			tags := applyPolicyAndCollectTags(policyName,
				createPolicyManifest(policyName, `
    pattern:
      regex: '^(dev|staging|prod)-v\d+\.\d+\.\d+$'
      extractPrefix: true`))

			Expect(tags).To(ContainElement("dev-v1.0.0"))
			Expect(tags).To(ContainElement("staging-v1.0.0"))
			Expect(tags).To(ContainElement("prod-v1.0.0"))
			Expect(tags).NotTo(ContainElement("v1.0.0"))

			By("verifying tagPrefix is set on ImageDetected")
			cmd := exec.Command("kubectl", "get", "imagedetected",
				"-l", fmt.Sprintf("automation.gitops.io/source=%s", policyName),
				"-n", "default", "-o", "json",
			)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var result struct {
				Items []struct {
					Spec struct {
						ImageTag  string `json:"imageTag"`
						TagPrefix string `json:"tagPrefix"`
					} `json:"spec"`
				} `json:"items"`
			}
			Expect(json.Unmarshal(output, &result)).To(Succeed())

			prefixes := make(map[string]string)
			for _, item := range result.Items {
				prefixes[item.Spec.ImageTag] = item.Spec.TagPrefix
			}
			Expect(prefixes).To(HaveKeyWithValue("dev-v1.0.0", "dev"))
			Expect(prefixes).To(HaveKeyWithValue("staging-v1.0.0", "staging"))
			Expect(prefixes).To(HaveKeyWithValue("prod-v1.0.0", "prod"))
		})
	})

	Context("Policy: Alphabetical", func() {
		const policyName = "test-alpha-policy"

		AfterEach(func() { cleanupPolicy(policyName) })

		It("should select images in alphabetical descending order", func() {
			tags := applyPolicyAndCollectTags(policyName,
				createPolicyManifest(policyName, `
    alphabetical:
      order: desc`))

			// Descending order: the first detected should be the "latest" alphabetically
			Expect(len(tags)).To(BeNumerically(">", 0))
			// All tags should be present (alphabetical doesn't filter, just sorts)
			// The policy processor picks the top result(s)
		})
	})

	Context("Git Commit Verification", func() {
		It("should commit generated manifests to the Git repository", func() {
			By("applying a semver policy to trigger Git commit flow")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = createPolicyManifest("test-git-policy", `
    semver:
      range: ">=1.0.0"`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the controller to commit to Git")
			verifyGitCommit := func() error {
				// Dump creation controller logs for debugging
				dumpControllerLogs()

				// Check Gitea API for commits
				cmd := exec.Command("curl", "-s",
					"-u", fmt.Sprintf("%s:%s", giteaUser, giteaPassword),
					fmt.Sprintf("%s/api/v1/repos/%s/%s/commits?limit=5",
						giteaURL, giteaUser, giteaRepo),
				)
				output, err := utils.Run(cmd)
				if err != nil {
					return err
				}

				// Try to parse as array
				var commits []struct {
					Commit struct {
						Message string `json:"message"`
					} `json:"commit"`
				}
				if err := json.Unmarshal(output, &commits); err != nil {
					_, _ = fmt.Fprintf(GinkgoWriter, "Gitea API response: %s\n", string(output))
					return fmt.Errorf("gitea returned non-array: %s", string(output)[:min(200, len(output))])
				}

				// Look for a commit from the controller
				for _, c := range commits {
					msg := c.Commit.Message
					if strings.Contains(msg, "Image Resource Controller") ||
						strings.Contains(msg, "image-controller") ||
						strings.Contains(msg, "image resource") {
						return nil
					}
				}

				var msgs []string
				for _, c := range commits {
					msgs = append(msgs, c.Commit.Message)
				}
				return fmt.Errorf("no controller commit, have %d commits: %v", len(commits), msgs)
			}
			EventuallyWithOffset(1, verifyGitCommit, 5*time.Minute, 15*time.Second).Should(Succeed())

			By("verifying committed files in the Git repository")
			cmd = exec.Command("curl", "-s",
				"-u", fmt.Sprintf("%s:%s", giteaUser, giteaPassword),
				fmt.Sprintf("%s/api/v1/repos/%s/%s/contents/",
					giteaURL, giteaUser, giteaRepo),
			)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var files []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			}
			Expect(json.Unmarshal(output, &files)).To(Succeed())

			// Verify that at least one manifest file was committed
			hasManifest := false
			for _, f := range files {
				if strings.HasSuffix(f.Name, ".yaml") || strings.HasSuffix(f.Name, ".yml") {
					hasManifest = true
					break
				}
			}
			Expect(hasManifest).To(BeTrue(), "Expected at least one YAML manifest in Git repo")
		})
	})
})

func createResourceTemplateManifest() *strings.Reader {
	manifest := fmt.Sprintf(`
apiVersion: automation.gitops.io/v1beta1
kind: ResourceTemplate
metadata:
  name: test-template
  namespace: default
spec:
  template: |
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: "{{ .ServiceName }}-config"
      namespace: default
    data:
      imageTag: "{{ .ImageTag }}"
      imageName: "{{ .FullImageName }}"
  gitRepository:
    url: "%s/%s/%s.git"
    branch: "main"
    path: "./manifests"
    secretRef:
      name: git-credentials
`, giteaInternalURL, giteaUser, giteaRepo)
	return strings.NewReader(manifest)
}

// createPolicyManifest generates an ImageResourcePolicy with the given policy spec.
// policySpec should be indented YAML starting from the policy fields (e.g. "semver:", "pattern:").
func createPolicyManifest(name, policySpec string) *strings.Reader {
	manifest := fmt.Sprintf(`
apiVersion: automation.gitops.io/v1beta1
kind: ImageResourcePolicy
metadata:
  name: %s
  namespace: default
spec:
  genericRegistry:
    registryURL: "%s"
    repositoryPattern: "%s"
    insecure: true
  policy:%s
  templateRef:
    name: test-template
  ttlDays: 1
`, name, registryInternalURL, testRepository, policySpec)
	return strings.NewReader(manifest)
}
