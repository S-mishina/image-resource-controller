# Makefile Guide

This document describes all available Make targets for the Image Resource Controller project.

## Quick Reference

```bash
make help                    # Show all available targets with descriptions
```

## Development Workflow

### Local Development

```bash
make fmt                     # Format Go code
make vet                     # Run go vet
make test                    # Run unit tests
make lint                    # Run golangci-lint
make build                   # Build both controller binaries
```

### Docker Operations

```bash
make docker-build            # Build both controller Docker images
make docker-build-detection  # Build detection controller image only
make docker-build-creation   # Build creation controller image only
make docker-push             # Push both images to registry
```

### Kubernetes Deployment

```bash
make install                 # Install CRDs into cluster
make deploy-controllers      # Deploy both controllers
make undeploy-controllers    # Remove both controllers
make build-controllers-installer  # Generate deployment manifest
```

### KIND Development (Recommended for Development)

```bash
make kind-create             # Create KIND cluster
make kind-dev               # Build + Load + Deploy (complete workflow)
make kind-status            # Show controller status
make kind-logs-detection    # Follow detection controller logs
make kind-logs-creation     # Follow creation controller logs
make kind-restart           # Restart both controllers
make kind-clean             # Complete cleanup
```

## Detailed Target Categories

### Development Targets

| Target | Description |
|--------|-------------|
| `fmt` | Format Go code using `go fmt` |
| `vet` | Run `go vet` against code |
| `test` | Run unit tests with coverage |
| `test-e2e` | Run end-to-end tests |
| `lint` | Run golangci-lint linter |
| `lint-fix` | Run golangci-lint with automatic fixes |

### Build Targets

| Target | Description |
|--------|-------------|
| `build` | Build both controller binaries |
| `build-detection` | Build detection controller binary only |
| `build-creation` | Build creation controller binary only |
| `run-detection` | Run detection controller from source |
| `run-creation` | Run creation controller from source |

### Docker Targets

| Target | Description |
|--------|-------------|
| `docker-build` | Build both Docker images |
| `docker-build-detection` | Build detection controller image |
| `docker-build-creation` | Build creation controller image |
| `docker-push` | Push both images to registry |
| `docker-push-detection` | Push detection controller image |
| `docker-push-creation` | Push creation controller image |

### Kubernetes Deployment Targets

| Target | Description |
|--------|-------------|
| `install` | Install CRDs into K8s cluster |
| `uninstall` | Remove CRDs from K8s cluster |
| `deploy-controllers` | Deploy both controllers to K8s |
| `undeploy-controllers` | Remove both controllers from K8s |
| `build-controllers-installer` | Generate `dist/controllers-install.yaml` |

### KIND Development Targets

| Target | Description |
|--------|-------------|
| `kind-create` | Create KIND cluster named 'image-resource-controller' |
| `kind-delete` | Delete the KIND cluster |
| `kind-load-images` | Load both controller images into KIND |
| `kind-deploy` | Load images and deploy to KIND |
| `kind-dev` | Complete dev workflow: build → load → deploy |
| `kind-status` | Show deployments, pods, services status |
| `kind-logs-detection` | Follow detection controller logs |
| `kind-logs-creation` | Follow creation controller logs |
| `kind-restart` | Restart both controllers (fast iteration) |
| `kind-clean` | Undeploy + delete KIND cluster |

### Code Generation Targets

| Target | Description |
|--------|-------------|
| `manifests` | Generate CRDs, RBAC, and webhook configurations |
| `generate` | Generate DeepCopy methods for Go structs |

## Common Development Workflows

### 1. Initial Setup

```bash
# Clone repository and setup
git clone <repository>
cd image-resource-controller
make kind-create && make kind-dev
```

### 2. Code Development Loop

```bash
# Make code changes
vim internal/controller/...

# Test locally
make test
make lint

# Deploy and test in KIND
make kind-dev
make kind-logs-detection
```

### 3. Before Committing

```bash
make fmt                     # Format code
make lint                    # Check linting
make test                    # Run tests
make docker-build            # Ensure images build
```

### 4. Production Deployment

```bash
# Build and push images
make docker-build
make docker-push

# Generate deployment manifest
make build-controllers-installer

# Deploy to production cluster
kubectl apply -f dist/controllers-install.yaml
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DETECTION_IMG` | `image-detection-controller:latest` | Detection controller image tag |
| `CREATION_IMG` | `resource-creation-controller:latest` | Creation controller image tag |
| `CONTAINER_TOOL` | `docker` | Container tool (docker/podman) |
| `KUBECTL` | `kubectl` | kubectl binary path |

### Custom Image Tags

```bash
# Use custom image tags
make docker-build DETECTION_IMG=myregistry/detection:v1.0.0 CREATION_IMG=myregistry/creation:v1.0.0

# Deploy with custom images
make kind-dev DETECTION_IMG=myregistry/detection:v1.0.0 CREATION_IMG=myregistry/creation:v1.0.0
```

## Manual Testing & Development

### Local Controller Execution

For manual testing without Kubernetes cluster:

#### 1. Detection Controller (Local)

```bash
# Set up AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Run detection controller locally
go run ./cmd/detection/main.go \
  --metrics-bind-address=:8080 \
  --health-probe-bind-address=:8081

# In another terminal, check health
curl http://localhost:8081/healthz
curl http://localhost:8081/readyz
```

#### 2. Creation Controller (Local)

```bash
# Set up Git credentials (if needed)
export GITHUB_TOKEN="your-github-token"

# Run creation controller locally
go run ./cmd/creation/main.go \
  --metrics-bind-address=:8082 \
  --health-probe-bind-address=:8083

# In another terminal, check health
curl http://localhost:8083/healthz
curl http://localhost:8083/readyz
```

#### 3. Both Controllers with Custom Kubeconfig

```bash
# Use specific kubeconfig
export KUBECONFIG="$HOME/.kube/dev-cluster"

# Terminal 1: Detection Controller
go run ./cmd/detection/main.go --metrics-bind-address=:8080

# Terminal 2: Creation Controller  
go run ./cmd/creation/main.go --metrics-bind-address=:8082
```

### Environment Setup Scripts

#### AWS Environment Setup

```bash
# Create .env.aws file
cat > .env.aws <<EOF
export AWS_ACCESS_KEY_ID="your-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
export AWS_DEFAULT_REGION="us-east-1"
EOF

# Source it
source .env.aws
```

#### Development Environment Setup

```bash
# Create .env.dev file
cat > .env.dev <<EOF
export KUBECONFIG="$HOME/.kube/kind-config-image-resource-controller"
export GITHUB_TOKEN="your-github-token"
export LOG_LEVEL="debug"
EOF

# Source it
source .env.dev
```

## Tips & Best Practices

### Development Tips

- Use `make kind-dev` for fastest iteration cycle
- Use `make kind-restart` for quick restarts without rebuilding images
- Use `make kind-logs-detection` in a separate terminal for log monitoring
- Run `make help` anytime to see available targets
- Use `go run` with environment variables for quick manual testing
- Create `.env.*` files for different environment setups

### CI/CD Integration

```bash
# Typical CI pipeline
make fmt
make lint
make test
make docker-build
make build-controllers-installer
```

### Debugging

```bash
# Check what Make will execute (dry run)
make -n kind-dev

# Verbose output
make -v kind-dev

# Check specific target dependencies
make -p | grep kind-dev
```

## Tool Dependencies

The following tools are automatically downloaded when needed:

- `kustomize` (v5.4.2)
- `controller-gen` (v0.15.0)
- `setup-envtest` (release-0.18)
- `golangci-lint` (v1.59.1)

Manual installation is not required - Make will handle tool dependencies automatically.
