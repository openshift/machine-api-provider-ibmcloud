#!/usr/bin/env bash

set -eu

REPO=github.com/openshift/machine-api-provider-ibmcloud
GOFLAGS=${GOFLAGS:--mod=vendor}
GLDFLAGS=${GLDFLAGS:-}

eval $(go env | grep -e "GOHOSTOS" -e "GOHOSTARCH")

GOOS=${GOOS:-${GOHOSTOS}}
GOARCH=${GOARCH:-${GOHOSTARCH}}

# Go to the root of the repo
cd "$(git rev-parse --show-cdup)"

VERSION_OVERRIDE=${VERSION_OVERRIDE:-${OS_GIT_VERSION:-}}
if [ -z "${VERSION_OVERRIDE:-}" ]; then
	echo "Using version from git..."
	VERSION_OVERRIDE="v0.0.0-$(git log -n1 --format=%h)"
fi

GLDFLAGS+="-X ${REPO}/pkg/version.Raw=${VERSION_OVERRIDE}"

eval $(go env)

if [ -z ${BIN_PATH+a} ]; then
	export BIN_PATH=_output/${GOOS}/${GOARCH}
fi

mkdir -p ${BIN_PATH}

echo "Building ${REPO} (${VERSION_OVERRIDE})"
GOOS=${GOOS} GOARCH=${GOARCH} go build ${GOFLAGS} -ldflags "${GLDFLAGS}" -o ${BIN_PATH}/machine-controller-manager ${REPO}/cmd/...
