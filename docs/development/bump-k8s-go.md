# Bumping Kubernetes and Go

This document describes how to bump Kubernetes and Go versions across the
project. It is primarily intended to be consumed by an AI coding agent (e.g. via
`/bump-k8s-go 1.36 1.26`), but the steps can also be followed manually.

The first argument is the target **Kubernetes minor** version (e.g. `1.36`) and
the second is the target **Go minor** version (e.g. `1.26`).

## Prerequisites

This repository depends on several OpenShift repositories that must be bumped
**before** this one. Each prerequisite repository must have a merged PR that
targets the same Kubernetes and Go versions. Verify all of these before
proceeding:

### openshift/api

The OpenShift API types repository must be bumped first. It defines the shared
API types consumed by all other OpenShift components.

```bash
gh pr list --repo openshift/api --state merged \
  --search "bump k8s ${K8S_MINOR} OR k8s ${K8S_MINOR}" \
  --limit 5
```

Record the commit SHA from the merged PR. Call this `OPENSHIFT_API_COMMIT`.

### openshift/client-go

The generated client library for OpenShift API types must be updated to match
the new `openshift/api`.

```bash
gh pr list --repo openshift/client-go --state merged \
  --search "bump k8s ${K8S_MINOR} OR k8s ${K8S_MINOR}" \
  --limit 5
```

Record the commit SHA. Call this `OPENSHIFT_CLIENT_GO_COMMIT`.

### openshift/library-go

Shared OpenShift library code, which depends on both `openshift/api` and
`openshift/client-go`.

```bash
gh pr list --repo openshift/library-go --state merged \
  --search "bump k8s ${K8S_MINOR} OR k8s ${K8S_MINOR}" \
  --limit 5
```

Record the commit SHA. Call this `OPENSHIFT_LIBRARY_GO_COMMIT`.

### openshift/machine-api-operator (MAO)

The machine-api-operator is the most critical prerequisite. This provider
imports types and test helpers from MAO, and MAO itself depends on the three
repositories above.

```bash
gh pr list --repo openshift/machine-api-operator --state merged \
  --search "bump k8s ${K8S_MINOR} OR k8s ${K8S_MINOR}" \
  --limit 5
```

Record the commit SHA (the pseudo-version). Call this `MAO_COMMIT`.

### Envtest assets (openshift/api)

The `unit` Makefile target downloads envtest binaries (etcd, kube-apiserver)
from an OpenShift-maintained index at
[openshift/api/envtest-releases.yaml](https://github.com/openshift/api/blob/master/envtest-releases.yaml).
Assets must be published for the target k8s version before the bump can proceed.

Check availability:

```bash
gh api repos/openshift/api/contents/envtest-releases.yaml \
  --jq '.content' | base64 -d | grep "v${K8S_MINOR}"
```

This should return one or more `v${K8S_MINOR}.X:` entries. The **highest patch
version** listed is what `ENVTEST_K8S_VERSION` in the Makefile should be set to.
Call this `ENVTEST_K8S_VERSION`.

If **no entry exists** for the target k8s minor, **stop**. The envtest assets
must be published first — tests will fail without them.

### Prerequisite verification

Before continuing, confirm that each prerequisite's `go.mod` targets the
expected `k8s.io/*` version and Go version:

```bash
for repo in openshift/api openshift/client-go openshift/library-go openshift/machine-api-operator; do
  echo "=== $repo ==="
  gh api "repos/$repo/contents/go.mod" --jq '.content' | base64 -d \
    | grep -E '^go |k8s.io/api ' | head -2
done
```

If any prerequisite is not yet bumped, **stop** and bump it first (or wait for
the responsible team to merge their PR).

## Step 1: Research

Perform these lookups before making any changes. Call the first argument
`K8S_MINOR` and the second `GO_MINOR`.

### 1a. Kubernetes patch version

Find the latest stable patch for the target k8s minor:

```bash
gh api repos/kubernetes/kubernetes/releases \
  --paginate --jq '.[].tag_name' \
  | grep "^v${K8S_MINOR}\." | grep -v -E '(alpha|beta|rc)' | head -1
```

Call this `K8S_VERSION` (e.g. `v1.36.2`).

### 1b. controller-runtime version

Find the controller-runtime version that targets the new k8s minor. Check which
version the MAO bump uses, or look at the controller-runtime releases:

```bash
gh api repos/kubernetes-sigs/controller-runtime/releases \
  --paginate --jq '.[].tag_name' | head -20
```

Cross-reference with MAO's `go.mod` to ensure compatibility:

```bash
gh api repos/openshift/machine-api-operator/contents/go.mod \
  --jq '.content' | base64 -d | grep 'sigs.k8s.io/controller-runtime'
```

Call this `CONTROLLER_RUNTIME_VERSION` (e.g. `v0.24.1`).

### 1c. controller-tools version

Check if controller-tools needs bumping:

```bash
gh api repos/kubernetes-sigs/controller-tools/releases \
  --paginate --jq '.[].tag_name' | head -10
```

Call this `CONTROLLER_TOOLS_VERSION`.

### 1d. OpenShift release mapping

Determine the target OpenShift release version that corresponds to this k8s
bump. The mapping is roughly:

| k8s minor | OCP version |
|-----------|-------------|
| 1.28      | 4.15        |
| 1.29      | 4.16        |
| 1.30      | 4.17        |
| 1.31      | 4.18        |
| 1.32      | 4.19        |
| 1.33      | 4.20        |
| 1.34      | 4.21        |
| 1.35      | 4.22        |
| 1.36      | 5.0         |

Call this `OCP_VERSION`. This determines the builder image tags.

### 1e. Builder image availability

Verify that CI builder images exist for the target Go version and OCP release:

```
registry.ci.openshift.org/ocp/builder:rhel-9-golang-${GO_MINOR}-openshift-${OCP_VERSION}
```

And the base image:

```
registry.ci.openshift.org/ocp/${OCP_VERSION}:base-rhel9
```

### 1f. Breaking changes

Check the controller-runtime and k8s changelogs for breaking changes:

```bash
gh api repos/kubernetes-sigs/controller-runtime/releases \
  --jq '.[] | select(.tag_name | startswith("v0.XX")) | .body' | head -100
```

Also check if MAO's bump PR had any code changes beyond `go.mod`/vendor:

```bash
gh pr diff <MAO_PR_NUMBER> --repo openshift/machine-api-operator \
  -- '*.go' 'Makefile' 'Dockerfile*'
```

Note any required code changes.

## Step 2: Update go.mod

### 2a. Update Go version

```bash
go mod edit -go=${GO_MINOR}
```

### 2b. Bump Kubernetes dependencies

```bash
K8S_MOD_VERSION=v0.${K8S_MINOR##1.}.Y  # e.g. v0.36.2 for k8s 1.36.2

go get k8s.io/api@${K8S_MOD_VERSION}
go get k8s.io/apimachinery@${K8S_MOD_VERSION}
go get k8s.io/apiserver@${K8S_MOD_VERSION}
go get k8s.io/client-go@${K8S_MOD_VERSION}
go get k8s.io/component-base@${K8S_MOD_VERSION}
```

### 2c. Bump controller-runtime and controller-tools

```bash
go get sigs.k8s.io/controller-runtime@${CONTROLLER_RUNTIME_VERSION}
go get sigs.k8s.io/controller-tools@${CONTROLLER_TOOLS_VERSION}
```

### 2d. Bump OpenShift dependencies

Use the pseudo-version format `v0.0.0-YYYYMMDDHHMMSS-<commit-hash>` from the
prerequisite commits:

```bash
go get github.com/openshift/api@${OPENSHIFT_API_COMMIT}
go get github.com/openshift/library-go@${OPENSHIFT_LIBRARY_GO_COMMIT}
go get github.com/openshift/machine-api-operator@${MAO_COMMIT}
```

`openshift/client-go` is an indirect dependency — it will be pulled in
transitively via `openshift/machine-api-operator` and `openshift/library-go`.

## Step 3: Tidy and vendor

```bash
go mod tidy
go mod vendor
go mod verify
```

Or use the Makefile target:

```bash
make vendor
```

## Step 4: Update build infrastructure

### 4a. Makefile

Update `ENVTEST_K8S_VERSION` to the highest patch version available in the
[openshift/api envtest-releases.yaml](https://github.com/openshift/api/blob/master/envtest-releases.yaml)
index for the target k8s minor:

```makefile
ENVTEST_K8S_VERSION := ${ENVTEST_K8S_VERSION}
```

Update `BUILD_IMAGE` to the new builder image:

```makefile
BUILD_IMAGE ?= registry.ci.openshift.org/ocp/builder:rhel-9-golang-${GO_MINOR}-openshift-${OCP_VERSION}
```

### 4b. Dockerfile

Update the builder image in the `FROM` line:

```dockerfile
FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-${GO_MINOR}-openshift-${OCP_VERSION} AS builder
```

Also update the base image if the OCP version changed:

```dockerfile
FROM registry.ci.openshift.org/ocp/${OCP_VERSION}:base-rhel9
```

## Step 5: Apply code changes

Using the breaking changes identified in Step 1f, apply any required code
changes. This step varies per bump. Common categories from historical bumps
include:

- **Feature gate API changes**: k8s may change feature gate defaults or
  graduation levels. The k8s 1.35 bump required adding a `majorVersion`
  parameter to `features.NewFeatureGateOptions` in `cmd/manager/main.go`.

- **controller-runtime interface changes**: webhook interfaces, predicate
  signatures, or builder patterns may change between minor versions.

- **Deprecated API migrations**: check for usage of deprecated packages
  (e.g. `k8s.io/utils/pointer` should be migrated to `k8s.io/utils/ptr`).

Review the MAO bump diff for guidance on what code changes were needed there.

## Step 6: Validate

```bash
make build
make vet
make unit
make lint
```

Fix any failures before proceeding.

## Step 7: Commit

Create separate commits for distinct concerns. The typical commit structure for
a bump PR is:

1. **Build image bump** (Makefile only):
   ```
   Bump build image to golang-${GO_MINOR}-openshift-${OCP_VERSION}
   ```

2. **Dependency bump** (go.mod, go.sum):
   ```
   Bump deps to k8s ${K8S_MINOR}
   ```

3. **Vendor update** (vendor/ directory only):
   ```
   Update vendor with k8s ${K8S_MINOR}
   ```

4. **Code changes** (if any, in a separate commit):
   ```
   <describe the specific code change>
   ```

Do NOT push or create a PR unless the user asks.

## Pre-merge checklist

- [ ] `go.mod` — Go version, k8s.io/*, controller-runtime, controller-tools,
  OpenShift deps all updated
- [ ] Vendor — `go mod tidy && go mod vendor` ran cleanly, vendor directory updated
- [ ] `Makefile` — `ENVTEST_K8S_VERSION` matches envtest-releases.yaml, `BUILD_IMAGE` updated
- [ ] `Dockerfile` — builder and base images updated
- [ ] Code compiles — `make build` passes
- [ ] Tests pass — `make unit` passes
- [ ] Vet passes — `make vet` passes

## Troubleshooting

### go mod tidy fails with incompatible transitive dependencies

Check if MAO's `go.mod` has `replace` directives that need to be mirrored:

```bash
gh api repos/openshift/machine-api-operator/contents/go.mod \
  --jq '.content' | base64 -d | grep '^replace'
```

### Vendor conflicts

If `go mod vendor` produces unexpected diffs, run `rm -rf vendor && go mod vendor`
to rebuild from scratch.

### ENVTEST_K8S_VERSION assets not available

Envtest asset availability is checked as a prerequisite. If assets are missing,
the bump should not proceed — tests will fail in CI. Check with the
openshift/api maintainers.
