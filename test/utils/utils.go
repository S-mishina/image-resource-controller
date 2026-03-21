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

// Package utils provides helper functions for E2E tests.
package utils //nolint:revive // standard test utility package name

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // dot import is idiomatic for Ginkgo
)

const (
	prometheusOperatorVersion = "v0.72.0"
	prometheusOperatorURL     = "https://github.com/prometheus-operator/prometheus-operator/" +
		"releases/download/%s/bundle.yaml"

	certmanagerVersion = "v1.14.4"
	certmanagerURLTmpl = "https://github.com/jetstack/cert-manager/releases/download/%s/cert-manager.yaml"
)

func warnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
}

// InstallPrometheusOperator installs the prometheus Operator to be used to export the enabled metrics.
func InstallPrometheusOperator() error {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.Command("kubectl", "create", "-f", url)
	_, err := Run(cmd)
	return err
}

// Run executes the provided command within this context
func Run(cmd *exec.Cmd) ([]byte, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %s\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %s\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s failed with error: (%v) %s", command, err, string(output))
	}

	return output, nil
}

// UninstallPrometheusOperator uninstalls the prometheus
func UninstallPrometheusOperator() {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.Command("kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// UninstallCertManager uninstalls the cert manager
func UninstallCertManager() {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// InstallCertManager installs the cert manager bundle.
func InstallCertManager() error {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "apply", "-f", url)
	if _, err := Run(cmd); err != nil {
		return err
	}
	// Wait for cert-manager-webhook to be ready, which can take time if cert-manager
	// was re-installed after uninstalling on a cluster.
	cmd = exec.Command("kubectl", "wait", "deployment.apps/cert-manager-webhook",
		"--for", "condition=Available",
		"--namespace", "cert-manager",
		"--timeout", "5m",
	)

	_, err := Run(cmd)
	return err
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster
func LoadImageToKindClusterWithName(name string) error {
	cluster := "kind"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := exec.Command("kind", kindOptions...)
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// StartE2EInfra starts the E2E infrastructure (registry + gitea) via docker compose
func StartE2EInfra() error {
	projectDir, _ := GetProjectDir()
	composePath := projectDir + "/test/e2e/docker-compose.yaml"

	// Ensure kind network exists (Kind creates it, but we need it before compose)
	cmd := exec.Command("docker", "network", "create", "kind")
	// Ignore error if network already exists
	_, _ = cmd.CombinedOutput()

	cmd = exec.Command("docker", "compose", "-f", composePath, "up", "-d", "--wait")
	_, err := Run(cmd)
	return err
}

// StopE2EInfra stops the E2E infrastructure
func StopE2EInfra() {
	projectDir, _ := GetProjectDir()
	composePath := projectDir + "/test/e2e/docker-compose.yaml"

	cmd := exec.Command("docker", "compose", "-f", composePath, "down", "-v")
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// PushTestImageToRegistry pushes a test image to the local registry
func PushTestImageToRegistry(registryURL, repository, tag string) error {
	sourceImage := "busybox:latest"
	targetImage := fmt.Sprintf("%s/%s:%s", registryURL, repository, tag)

	// Pull source image
	cmd := exec.Command("docker", "pull", sourceImage)
	if _, err := Run(cmd); err != nil {
		return fmt.Errorf("failed to pull %s: %w", sourceImage, err)
	}

	// Tag for local registry
	cmd = exec.Command("docker", "tag", sourceImage, targetImage)
	if _, err := Run(cmd); err != nil {
		return fmt.Errorf("failed to tag image: %w", err)
	}

	// Push to local registry
	cmd = exec.Command("docker", "push", targetImage)
	if _, err := Run(cmd); err != nil {
		return fmt.Errorf("failed to push %s: %w", targetImage, err)
	}

	return nil
}

// SetupGiteaRepo creates a test user and repository in Gitea
func SetupGiteaRepo(giteaURL, username, password, repoName string) error {
	// Create admin user via docker exec (most reliable for fresh Gitea)
	cmd := exec.Command("docker", "exec", "--user", "git", "kind-gitea",
		"gitea", "admin", "user", "create",
		"--admin",
		"--username", "gitea_admin",
		"--password", "gitea_admin",
		"--email", "admin@test.local",
	)
	// Ignore error if admin already exists
	_, _ = cmd.CombinedOutput()

	// Create test user via admin API
	cmd = exec.Command("curl", "-s", "-X", "POST",
		fmt.Sprintf("%s/api/v1/admin/users", giteaURL),
		"-H", "Content-Type: application/json",
		"-u", "gitea_admin:gitea_admin",
		"-d", fmt.Sprintf(`{
			"username": "%s",
			"password": "%s",
			"email": "%s@test.local",
			"must_change_password": false,
			"visibility": "public"
		}`, username, password, username),
	)
	output, _ := Run(cmd)
	_, _ = fmt.Fprintf(GinkgoWriter, "Create user response: %s\n", string(output))

	// Create repository via user API
	cmd = exec.Command("curl", "-s", "-X", "POST",
		fmt.Sprintf("%s/api/v1/user/repos", giteaURL),
		"-H", "Content-Type: application/json",
		"-u", fmt.Sprintf("%s:%s", username, password),
		"-d", fmt.Sprintf(`{
			"name": "%s",
			"auto_init": true,
			"default_branch": "main"
		}`, repoName),
	)
	output, err := Run(cmd)
	_, _ = fmt.Fprintf(GinkgoWriter, "Create repo response: %s\n", string(output))
	return err
}

// CreateKindClusterWithRegistry creates a Kind cluster with local registry support
func CreateKindClusterWithRegistry(clusterName string) error {
	projectDir, _ := GetProjectDir()
	configPath := projectDir + "/test/e2e/kind-config.yaml"

	cmd := exec.Command("kind", "create", "cluster",
		"--name", clusterName,
		"--config", configPath,
	)
	if _, err := Run(cmd); err != nil {
		return fmt.Errorf("failed to create kind cluster: %w", err)
	}

	return nil
}

// DeleteKindCluster deletes a Kind cluster
func DeleteKindCluster(clusterName string) {
	cmd := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}
