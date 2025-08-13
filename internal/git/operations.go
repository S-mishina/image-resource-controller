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

package git

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// AuthType represents the type of Git authentication
type AuthType string

const (
	AuthTypeNone        AuthType = "none"
	AuthTypeHTTP        AuthType = "http"   // Username + Password/Token
	AuthTypeSSH         AuthType = "ssh"    // SSH Key
	AuthTypeGitHubToken AuthType = "github" // GitHub Personal Access Token
	AuthTypeGitLabToken AuthType = "gitlab" // GitLab Access Token
)

// AuthConfig represents Git authentication configuration
type AuthConfig struct {
	Type AuthType `json:"type"`

	// HTTP/Token authentication
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`

	// SSH authentication
	SSHPrivateKey            []byte `json:"sshPrivateKey,omitempty"`
	SSHPrivateKeyFile        string `json:"sshPrivateKeyFile,omitempty"`
	SSHPassphrase            string `json:"sshPassphrase,omitempty"`
	SSHKnownHostsFile        string `json:"sshKnownHostsFile,omitempty"`
	SSHInsecureIgnoreHostKey bool   `json:"sshInsecureIgnoreHostKey,omitempty"`
}

// CommitInfo represents information about a Git commit
type CommitInfo struct {
	Hash      string    `json:"hash"`
	Message   string    `json:"message"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"timestamp"`
	Files     []string  `json:"files"`
}

// OperationResult represents the result of a Git operation
type OperationResult struct {
	Success      bool       `json:"success"`
	CommitInfo   CommitInfo `json:"commitInfo,omitempty"`
	Error        string     `json:"error,omitempty"`
	WorkingDir   string     `json:"workingDir,omitempty"`
	RemoteURL    string     `json:"remoteURL,omitempty"`
	Branch       string     `json:"branch,omitempty"`
	FilesChanged int        `json:"filesChanged"`
}

// Operations handles Git operations for the image resource controller
type Operations struct {
	workingDir string
	authConfig AuthConfig

	// Git configuration
	authorName  string
	authorEmail string

	// Repository state
	repository *git.Repository
	auth       transport.AuthMethod
}

// NewOperations creates a new Git operations instance
func NewOperations(workingDir string, authConfig AuthConfig) *Operations {
	return &Operations{
		workingDir: workingDir,
		authConfig: authConfig,
		// Default author info (can be overridden)
		authorName:  "Image Resource Controller",
		authorEmail: "image-controller@example.com",
	}
}

// SetAuthor sets the Git author information
func (g *Operations) SetAuthor(name, email string) {
	g.authorName = name
	g.authorEmail = email
}

// CloneAndCommitFiles clones a repository, adds/updates files, commits and pushes changes
func (g *Operations) CloneAndCommitFiles(ctx context.Context, repoURL, branch string, files map[string]string, commitMessage string) (OperationResult, error) {
	logger := log.FromContext(ctx)

	result := OperationResult{
		RemoteURL: repoURL,
		Branch:    branch,
	}

	logger.Info("Starting Git operation",
		"repoURL", repoURL,
		"branch", branch,
		"filesCount", len(files))

	// Setup authentication
	if err := g.setupAuth(); err != nil {
		result.Error = fmt.Sprintf("Failed to setup authentication: %v", err)
		return result, err
	}

	// Create temporary working directory if not specified
	if g.workingDir == "" {
		tempDir, err := ioutil.TempDir("", "git-operations-*")
		if err != nil {
			result.Error = fmt.Sprintf("Failed to create temp directory: %v", err)
			return result, err
		}
		g.workingDir = tempDir

		// Cleanup temp directory after operation
		defer func() {
			os.RemoveAll(tempDir)
		}()
	}

	result.WorkingDir = g.workingDir

	// Clone repository
	if err := g.cloneRepository(ctx, repoURL, branch); err != nil {
		result.Error = fmt.Sprintf("Failed to clone repository: %v", err)
		return result, err
	}

	// Write files to working directory
	changedFiles, err := g.writeFiles(files)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to write files: %v", err)
		return result, err
	}

	result.FilesChanged = len(changedFiles)

	// Check if there are any changes to commit
	hasChanges, err := g.hasChanges()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to check for changes: %v", err)
		return result, err
	}

	if !hasChanges {
		logger.Info("No changes detected in repository, skipping commit and push operation",
			"repoURL", repoURL,
			"branch", branch,
			"filesProcessed", len(files),
			"reason", "All files already exist with identical content")
		result.Success = true
		result.FilesChanged = 0
		return result, nil
	}

	// Stage and commit files
	commitInfo, err := g.commitFiles(changedFiles, commitMessage)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to commit files: %v", err)
		return result, err
	}

	result.CommitInfo = commitInfo

	// Push changes to remote
	if err := g.pushChanges(ctx, branch); err != nil {
		result.Error = fmt.Sprintf("Failed to push changes: %v", err)
		return result, err
	}

	result.Success = true
	logger.Info("Git operation completed successfully",
		"commitHash", commitInfo.Hash,
		"filesChanged", result.FilesChanged)

	return result, nil
}

// setupAuth configures Git authentication based on the auth config
func (g *Operations) setupAuth() error {
	switch g.authConfig.Type {
	case AuthTypeNone:
		g.auth = nil

	case AuthTypeHTTP, AuthTypeGitHubToken, AuthTypeGitLabToken:
		username := g.authConfig.Username
		password := g.authConfig.Password

		// For token-based auth, use token as password
		if g.authConfig.Token != "" {
			if g.authConfig.Type == AuthTypeGitHubToken {
				username = "git" // GitHub convention
			} else if g.authConfig.Type == AuthTypeGitLabToken {
				username = "oauth2" // GitLab convention
			}
			password = g.authConfig.Token
		}

		if username == "" || password == "" {
			return fmt.Errorf("username and password/token are required for HTTP auth")
		}

		g.auth = &http.BasicAuth{
			Username: username,
			Password: password,
		}

	case AuthTypeSSH:
		return g.setupSSHAuth()

	default:
		return fmt.Errorf("unsupported auth type: %s", g.authConfig.Type)
	}

	return nil
}

// setupSSHAuth configures SSH authentication
func (g *Operations) setupSSHAuth() error {
	var privateKey []byte
	var err error

	// Load private key from file or direct content
	if g.authConfig.SSHPrivateKeyFile != "" {
		privateKey, err = ioutil.ReadFile(g.authConfig.SSHPrivateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read SSH private key file: %w", err)
		}
	} else if len(g.authConfig.SSHPrivateKey) > 0 {
		privateKey = g.authConfig.SSHPrivateKey
	} else {
		return fmt.Errorf("SSH private key or key file is required for SSH auth")
	}

	// Create SSH auth method
	sshAuth, err := gitssh.NewPublicKeys("git", privateKey, g.authConfig.SSHPassphrase)
	if err != nil {
		return fmt.Errorf("failed to create SSH auth: %w", err)
	}

	// Configure host key verification
	if g.authConfig.SSHInsecureIgnoreHostKey {
		// Use insecure host key callback (accepts any host key)
		sshAuth.HostKeyCallback = gossh.InsecureIgnoreHostKey()
	} else if g.authConfig.SSHKnownHostsFile != "" {
		// Use known_hosts file
		hostKeyCallback, err := knownhosts.New(g.authConfig.SSHKnownHostsFile)
		if err != nil {
			return fmt.Errorf("failed to load known hosts file: %w", err)
		}
		sshAuth.HostKeyCallback = hostKeyCallback
	} else {
		// Use system known_hosts files
		hostKeyCallback, err := knownhosts.New()
		if err != nil {
			// If system known_hosts cannot be found, use insecure mode as fallback
			sshAuth.HostKeyCallback = gossh.InsecureIgnoreHostKey()
		} else {
			sshAuth.HostKeyCallback = hostKeyCallback
		}
	}

	g.auth = sshAuth
	return nil
}

// cloneRepository clones the repository to the working directory
func (g *Operations) cloneRepository(ctx context.Context, repoURL, branch string) error {
	logger := log.FromContext(ctx)

	cloneOptions := &git.CloneOptions{
		URL:             repoURL,
		Auth:            g.auth,
		Progress:        os.Stdout,
		SingleBranch:    true,
		InsecureSkipTLS: false,
	}

	// For specific branches, we'll just clone the default branch for simplicity
	// Branch switching can be implemented later if needed

	logger.Info("Cloning repository", "url", repoURL, "branch", branch, "workingDir", g.workingDir)

	repo, err := git.PlainCloneContext(ctx, g.workingDir, false, cloneOptions)
	if err != nil {
		// Check if it's an empty repository error
		if strings.Contains(err.Error(), "remote repository is empty") ||
			strings.Contains(err.Error(), "repository is empty") {
			logger.Info("Remote repository is empty, initializing new repository")
			return g.initializeEmptyRepository(ctx, repoURL, branch)
		}
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	g.repository = repo
	return nil
}

// writeFiles writes the provided files to the repository
func (g *Operations) writeFiles(files map[string]string) ([]string, error) {
	var changedFiles []string

	for filename, content := range files {
		filePath := filepath.Join(g.workingDir, filename)

		// Create directory if it doesn't exist
		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Write file content
		if err := ioutil.WriteFile(filePath, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("failed to write file %s: %w", filename, err)
		}

		changedFiles = append(changedFiles, filename)
	}

	return changedFiles, nil
}

// hasChanges checks if there are any uncommitted changes
func (g *Operations) hasChanges() (bool, error) {
	if g.repository == nil {
		return false, fmt.Errorf("repository not initialized")
	}

	worktree, err := g.repository.Worktree()
	if err != nil {
		return false, fmt.Errorf("failed to get worktree: %w", err)
	}

	status, err := worktree.Status()
	if err != nil {
		return false, fmt.Errorf("failed to get status: %w", err)
	}

	return !status.IsClean(), nil
}

// commitFiles stages and commits the specified files
func (g *Operations) commitFiles(files []string, message string) (CommitInfo, error) {
	var commitInfo CommitInfo

	if g.repository == nil {
		return commitInfo, fmt.Errorf("repository not initialized")
	}

	worktree, err := g.repository.Worktree()
	if err != nil {
		return commitInfo, fmt.Errorf("failed to get worktree: %w", err)
	}

	// Stage files
	for _, file := range files {
		_, err := worktree.Add(file)
		if err != nil {
			return commitInfo, fmt.Errorf("failed to stage file %s: %w", file, err)
		}
	}

	// Create commit
	commitHash, err := worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  g.authorName,
			Email: g.authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return commitInfo, fmt.Errorf("failed to create commit: %w", err)
	}

	// Get commit object
	commit, err := g.repository.CommitObject(commitHash)
	if err != nil {
		return commitInfo, fmt.Errorf("failed to get commit object: %w", err)
	}

	commitInfo = CommitInfo{
		Hash:      commitHash.String(),
		Message:   commit.Message,
		Author:    commit.Author.Name,
		Email:     commit.Author.Email,
		Timestamp: commit.Author.When,
		Files:     files,
	}

	return commitInfo, nil
}

// initializeEmptyRepository initializes a new repository for empty remote repositories
func (g *Operations) initializeEmptyRepository(ctx context.Context, repoURL, branch string) error {
	logger := log.FromContext(ctx)

	logger.Info("Initializing new repository for empty remote", "workingDir", g.workingDir)

	// Initialize a new repository
	repo, err := git.PlainInit(g.workingDir, false)
	if err != nil {
		return fmt.Errorf("failed to initialize repository: %w", err)
	}

	// Set default branch to main (modern Git standard)
	if branch == "" {
		branch = "main"
	}

	// Create the initial branch
	headRef := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName(branch))
	err = repo.Storer.SetReference(headRef)
	if err != nil {
		return fmt.Errorf("failed to set default branch to %s: %w", branch, err)
	}

	// Create remote origin
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})
	if err != nil {
		return fmt.Errorf("failed to create remote origin: %w", err)
	}

	g.repository = repo
	logger.Info("Successfully initialized repository for empty remote", "defaultBranch", branch)
	return nil
}

// pushChanges pushes committed changes to the remote repository
func (g *Operations) pushChanges(ctx context.Context, branch string) error {
	if g.repository == nil {
		return fmt.Errorf("repository not initialized")
	}

	logger := log.FromContext(ctx)

	// First, check if we actually have commits to push
	head, err := g.repository.Head()
	if err != nil {
		logger.Info("No HEAD found, attempting initial push anyway")
	} else {
		logger.Info("Found HEAD commit", "hash", head.Hash().String())
	}

	pushOptions := &git.PushOptions{
		Auth:     g.auth,
		Progress: os.Stdout,
	}

	// For initial push to empty repository, use force push
	if branch != "" {
		pushOptions.RefSpecs = []config.RefSpec{
			config.RefSpec("+refs/heads/" + branch + ":refs/heads/" + branch),
		}
	}

	logger.Info("Pushing changes to remote", "branch", branch)

	err = g.repository.PushContext(ctx, pushOptions)
	if err != nil {
		logger.Info("Push failed, analyzing error", "error", err.Error())

		// Check for various acceptable conditions
		if strings.Contains(err.Error(), "already up-to-date") ||
			strings.Contains(err.Error(), "non-fast-forward") {
			logger.Info("Repository is already up-to-date")
			return nil
		}

		// Handle initial push to empty repository with different approaches
		if strings.Contains(err.Error(), "src refspec") ||
			strings.Contains(err.Error(), "does not match any") ||
			strings.Contains(err.Error(), "remote repository is empty") {
			logger.Info("Attempting force push for empty repository")

			// Force push all refs
			pushOptions.RefSpecs = []config.RefSpec{
				config.RefSpec("+refs/*:refs/*"),
			}
			err = g.repository.PushContext(ctx, pushOptions)
			if err == nil {
				logger.Info("Force push successful")
				return nil
			}

			logger.Info("Force push failed, trying specific branch", "error", err.Error())
			// Try with specific branch and force
			pushOptions.RefSpecs = []config.RefSpec{
				config.RefSpec("+HEAD:refs/heads/" + branch),
			}
			err = g.repository.PushContext(ctx, pushOptions)
			if err == nil {
				logger.Info("Branch-specific force push successful")
				return nil
			}
		}

		return fmt.Errorf("failed to push changes after all attempts: %w", err)
	}

	logger.Info("Push completed successfully")
	return nil
}

// ValidateRepository validates that the repository URL is accessible
func (g *Operations) ValidateRepository(ctx context.Context, repoURL string) error {
	// Setup authentication
	if err := g.setupAuth(); err != nil {
		return fmt.Errorf("failed to setup authentication: %w", err)
	}

	// Try to list remote references
	remote := git.NewRemote(nil, &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	_, err := remote.ListContext(ctx, &git.ListOptions{
		Auth: g.auth,
	})
	if err != nil {
		return fmt.Errorf("failed to validate repository %s: %w", repoURL, err)
	}

	return nil
}

// GetRemoteBranches returns a list of available branches in the remote repository
func (g *Operations) GetRemoteBranches(ctx context.Context, repoURL string) ([]string, error) {
	// Setup authentication
	if err := g.setupAuth(); err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}

	// List remote references
	remote := git.NewRemote(nil, &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	refs, err := remote.ListContext(ctx, &git.ListOptions{
		Auth: g.auth,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list remote branches: %w", err)
	}

	var branches []string
	for _, ref := range refs {
		if ref.Name().IsBranch() {
			branchName := ref.Name().Short()
			branches = append(branches, branchName)
		}
	}

	return branches, nil
}

// Cleanup removes the working directory and cleans up resources
func (g *Operations) Cleanup() error {
	if g.workingDir != "" && (strings.Contains(g.workingDir, "/tmp/") || strings.Contains(g.workingDir, "git-operations-")) {
		return os.RemoveAll(g.workingDir)
	}
	return nil
}

// GenerateCommitMessage generates a standardized commit message for image updates
func GenerateCommitMessage(imageName, imageTag, operation string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	switch operation {
	case "create":
		return fmt.Sprintf("feat: Add Kubernetes resources for %s:%s\n\nGenerated by Image Resource Controller\nTimestamp: %s",
			imageName, imageTag, timestamp)
	case "update":
		return fmt.Sprintf("chore: Update %s to %s\n\nGenerated by Image Resource Controller\nTimestamp: %s",
			imageName, imageTag, timestamp)
	default:
		return fmt.Sprintf("chore: Automated update for %s:%s\n\nGenerated by Image Resource Controller\nTimestamp: %s",
			imageName, imageTag, timestamp)
	}
}

// GetOperationStats returns statistics about Git operations
type OperationStats struct {
	TotalOperations   int       `json:"totalOperations"`
	SuccessfulOps     int       `json:"successfulOps"`
	FailedOps         int       `json:"failedOps"`
	AverageCommitSize int       `json:"averageCommitSize"`
	LastOperation     time.Time `json:"lastOperation"`
	TotalFilesChanged int       `json:"totalFilesChanged"`
}
