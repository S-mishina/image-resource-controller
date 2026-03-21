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

package generic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// setupMockRegistry creates a mock Docker Registry HTTP API V2 server
func setupMockRegistry() *httptest.Server {
	mux := http.NewServeMux()

	// GET /v2/ - API version check
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// GET /v2/_catalog - List repositories
	mux.HandleFunc("/v2/_catalog", func(w http.ResponseWriter, r *http.Request) {
		resp := catalogResponse{
			Repositories: []string{"app-a", "app-b", "team/service-x"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// GET /v2/app-a/tags/list
	mux.HandleFunc("/v2/app-a/tags/list", func(w http.ResponseWriter, r *http.Request) {
		resp := tagsResponse{
			Name: "app-a",
			Tags: []string{"v1.0.0", "v1.1.0", "latest"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// GET /v2/app-b/tags/list
	mux.HandleFunc("/v2/app-b/tags/list", func(w http.ResponseWriter, r *http.Request) {
		resp := tagsResponse{
			Name: "app-b",
			Tags: []string{"v2.0.0"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// GET /v2/team/service-x/tags/list
	mux.HandleFunc("/v2/team/service-x/tags/list", func(w http.ResponseWriter, r *http.Request) {
		resp := tagsResponse{
			Name: "team/service-x",
			Tags: []string{"v1.0.0"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// GET /v2/app-a/manifests/<tag>
	mux.HandleFunc("/v2/app-a/manifests/", func(w http.ResponseWriter, r *http.Request) {
		manifest := manifestResponse{
			SchemaVersion: 2,
			MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		}
		manifest.Config.MediaType = "application/vnd.docker.container.image.v1+json"
		manifest.Config.Size = 1024
		manifest.Config.Digest = "sha256:config123"
		manifest.Layers = []struct {
			MediaType string `json:"mediaType"`
			Size      int64  `json:"size"`
			Digest    string `json:"digest"`
		}{
			{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Size: 2048, Digest: "sha256:layer1"},
			{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Size: 4096, Digest: "sha256:layer2"},
		}

		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("Docker-Content-Digest", "sha256:abc123def456")
		json.NewEncoder(w).Encode(manifest)
	})

	return httptest.NewServer(mux)
}

func TestHealthCheck(t *testing.T) {
	server := setupMockRegistry()
	defer server.Close()

	reg := &GenericRegistry{
		httpClient:  server.Client(),
		registryURL: server.URL,
	}

	err := reg.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
}

func TestHealthCheck_NoURL(t *testing.T) {
	reg := &GenericRegistry{
		httpClient: http.DefaultClient,
	}

	err := reg.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("HealthCheck() expected error for empty URL")
	}
}

func TestValidateConfig(t *testing.T) {
	reg := &GenericRegistry{}

	tests := []struct {
		name    string
		config  RegistryConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: RegistryConfig{
				Type:           RegistryTypeGeneric,
				RepositoryName: "app-a",
				RegistryURL:    "http://localhost:5000",
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			config: RegistryConfig{
				Type:           "ecr",
				RepositoryName: "app-a",
				RegistryURL:    "http://localhost:5000",
			},
			wantErr: true,
		},
		{
			name: "missing URL",
			config: RegistryConfig{
				Type:           RegistryTypeGeneric,
				RepositoryName: "app-a",
			},
			wantErr: true,
		},
		{
			name: "missing repository",
			config: RegistryConfig{
				Type:        RegistryTypeGeneric,
				RegistryURL: "http://localhost:5000",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reg.ValidateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScanRepository(t *testing.T) {
	server := setupMockRegistry()
	defer server.Close()

	reg := &GenericRegistry{
		httpClient: server.Client(),
	}

	config := RegistryConfig{
		Type:           RegistryTypeGeneric,
		RepositoryName: "app-a",
		RegistryURL:    server.URL,
	}

	images, err := reg.ScanRepository(context.Background(), config)
	if err != nil {
		t.Fatalf("ScanRepository() error = %v", err)
	}

	if len(images) != 3 {
		t.Fatalf("ScanRepository() got %d images, want 3", len(images))
	}

	// Verify tags
	tags := make(map[string]bool)
	for _, img := range images {
		tags[img.Tag] = true
		if img.Name != "app-a" {
			t.Errorf("expected name 'app-a', got '%s'", img.Name)
		}
		if img.FullURL == "" {
			t.Error("expected FullURL to be set")
		}
	}

	for _, expected := range []string{"v1.0.0", "v1.1.0", "latest"} {
		if !tags[expected] {
			t.Errorf("missing expected tag: %s", expected)
		}
	}

	// Check manifest info was fetched
	for _, img := range images {
		if img.Digest == "" {
			t.Errorf("expected digest for tag %s", img.Tag)
		}
		if img.Size == 0 {
			t.Errorf("expected size > 0 for tag %s", img.Tag)
		}
	}
}

func TestFindRepositoriesByPattern(t *testing.T) {
	server := setupMockRegistry()
	defer server.Close()

	reg := &GenericRegistry{
		httpClient:  server.Client(),
		registryURL: server.URL,
	}

	tests := []struct {
		name     string
		pattern  string
		maxRepos int32
		want     int
	}{
		{name: "match with wildcard", pattern: "app-*", maxRepos: 10, want: 2},
		{name: "exact match", pattern: "app-a", maxRepos: 10, want: 1},
		{name: "no match", pattern: "xyz-*", maxRepos: 10, want: 0},
		{name: "nested repo", pattern: "team/*", maxRepos: 10, want: 1},
		{name: "limit results", pattern: "app-*", maxRepos: 1, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repos, err := reg.FindRepositoriesByPattern(
				context.Background(), "", tt.pattern, tt.maxRepos,
			)
			if err != nil {
				t.Fatalf("FindRepositoriesByPattern() error = %v", err)
			}
			if len(repos) != tt.want {
				t.Errorf("got %d repos, want %d", len(repos), tt.want)
			}
		})
	}
}

func TestScanRepositoriesByPattern(t *testing.T) {
	server := setupMockRegistry()
	defer server.Close()

	reg := &GenericRegistry{
		httpClient:  server.Client(),
		registryURL: server.URL,
	}

	images, err := reg.ScanRepositoriesByPattern(
		context.Background(), "", "app-*", 10,
	)
	if err != nil {
		t.Fatalf("ScanRepositoriesByPattern() error = %v", err)
	}

	// app-a has 3 tags, app-b has 1 tag
	if len(images) != 4 {
		t.Errorf("got %d images, want 4", len(images))
	}
}

func TestScanByImagePattern(t *testing.T) {
	server := setupMockRegistry()
	defer server.Close()

	reg := &GenericRegistry{
		httpClient:  server.Client(),
		registryURL: server.URL,
	}

	images, err := reg.ScanByImagePattern(
		context.Background(), "", "app-a:v1.*", 10,
	)
	if err != nil {
		t.Fatalf("ScanByImagePattern() error = %v", err)
	}

	if len(images) != 2 {
		t.Errorf("got %d images, want 2", len(images))
	}
}

func TestScanByImagePattern_InvalidFormat(t *testing.T) {
	reg := &GenericRegistry{
		httpClient:  http.DefaultClient,
		registryURL: "http://localhost",
	}

	_, err := reg.ScanByImagePattern(
		context.Background(), "", "no-colon-pattern", 10,
	)
	if err == nil {
		t.Fatal("expected error for invalid pattern format")
	}
}

func TestAuthenticate_BasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reg := &GenericRegistry{
		httpClient:  server.Client(),
		registryURL: server.URL,
	}

	err := reg.Authenticate(context.Background(), AuthConfig{
		Username: "testuser",
		Password: "testpass",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	// Verify auth is used in health check
	err = reg.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("HealthCheck with auth failed: %v", err)
	}
}

func TestGetRegistryType(t *testing.T) {
	reg := &GenericRegistry{}
	if reg.GetRegistryType() != RegistryTypeGeneric {
		t.Errorf("got %s, want %s", reg.GetRegistryType(), RegistryTypeGeneric)
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		text    string
		pattern string
		want    bool
	}{
		{"app-a", "app-*", true},
		{"app-a", "app-a", true},
		{"app-a", "app-b", false},
		{"app-a", "*-a", true},
		{"app-a", "*", true},
		{"team/service", "team/*", true},
		{"team/service", "other/*", false},
		{"v1.0.0", "v1.*", true},
		{"v2.0.0", "v1.*", false},
	}

	for _, tt := range tests {
		t.Run(tt.text+"_"+tt.pattern, func(t *testing.T) {
			got := matchWildcard(tt.text, tt.pattern)
			if got != tt.want {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v",
					tt.text, tt.pattern, got, tt.want)
			}
		})
	}
}
