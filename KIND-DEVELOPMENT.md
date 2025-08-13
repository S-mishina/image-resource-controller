# KIND Development Guide

This guide explains the development workflow using KIND clusters for the Image Resource Controller project.

## Quick Start

### 1. One-Command Setup: Create KIND Cluster + Build + Deploy

```bash
# Create KIND cluster → Build images → Deploy controllers
make kind-create && make kind-dev
```

### 2. Check Status

```bash
make kind-status
```

### 3. View Logs

```bash
# Detection Controller logs
make kind-logs-detection

# Creation Controller logs
make kind-logs-creation
```

### 4. Development Iteration

```bash
# After code changes, rebuild and redeploy
make kind-dev

# Or just restart controllers (faster)
make kind-restart
```

### 5. Complete Cleanup

```bash
make kind-clean
```

## Available Make Targets

### KIND Development Targets

- `kind-create` - Create a KIND cluster named 'image-resource-controller'
- `kind-delete` - Delete the KIND cluster
- `kind-load-images` - Load both controller images into KIND cluster
- `kind-deploy` - Load images and deploy controllers to KIND cluster
- `kind-dev` - Complete development workflow: build, load images, and deploy
- `kind-logs-detection` - Show detection controller logs (follow mode)
- `kind-logs-creation` - Show creation controller logs (follow mode)
- `kind-status` - Show status of deployments, pods, and services
- `kind-restart` - Restart both controllers
- `kind-clean` - Complete cleanup: undeploy controllers and delete cluster

## Troubleshooting

### Images Not Reflecting Changes

```bash
# Rebuild images and redeploy
make docker-build
make kind-load-images
make kind-restart
```

### Pods Not Starting

```bash
# Check detailed pod status
kubectl describe pods -n image-resource-controller-system

# Check logs
make kind-logs-detection
make kind-logs-creation
```

### Check Resource Status

```bash
# See all resources in the controller namespace
kubectl get all -n image-resource-controller-system

# Check CRDs
kubectl get crd | grep automation.gitops.io
```

## Notes

- The KIND cluster is named `image-resource-controller` to avoid conflicts
- Images are tagged as `image-detection-controller:latest` and `resource-creation-controller:latest`
- All resources are deployed in the `image-resource-controller-system` namespace
- Log commands use `-f` flag for follow mode - use Ctrl+C to exit
