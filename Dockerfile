FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.22 AS builder
WORKDIR /go/src/github.com/openshift/machine-api-provider-ibmcloud

COPY . .
# VERSION env gets set in the openshift/release image and refers to the golang version, which interfers with our own
RUN unset VERSION \
 && GOPROXY=off NO_DOCKER=1 make build
RUN mkdir -p /tmp/build && cp _output/linux/$(go env GOARCH)/machine-controller-manager /tmp/build/machine-controller-manager

FROM registry.ci.openshift.org/ocp/4.22:base-rhel9-minimal
COPY --from=builder /tmp/build/machine-controller-manager /
