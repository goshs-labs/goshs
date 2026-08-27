# Stage 1: Build the Go application
# Pin the builder to the build host's native platform and cross-compile to the
# requested target. This avoids running the (slow) Go toolchain under QEMU when
# building multi-arch images with buildx.
#
# BUILDPLATFORM is predefined by buildx, but the classic builder (used by the
# testcontainers integration build) does not set it — without a default it would
# expand to an empty `--platform=` and fail. The default only takes effect on
# that path; buildx overrides it per build. It selects the builder node only and
# never affects the produced binary's architecture (that is TARGETARCH below).
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder

# Provided automatically by buildx for each target platform.
ARG TARGETOS
ARG TARGETARCH

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Coverage instrumentation is opt-in via the COVER build arg (pass
# --build-arg COVER=-cover); it stays OFF for released images so they ship a
# clean, uninstrumented binary. The integration tests enable it to collect
# covdata. goshs is cgo-free, so CGO_ENABLED=0 yields a static binary that runs
# in the minimal alpine stage; -trimpath and -s -w shrink it and make the build
# reproducible (matching .goreleaser.yml).
ARG COVER=""
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" ${COVER} -o /goshs .

# Stage 2: Create a minimal runtime image
FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /goshs .

# Command to run the executable
ENTRYPOINT ["./goshs"]
