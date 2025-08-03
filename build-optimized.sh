#!/bin/bash

# Optimized build script for Zeek Docker image
# This script uses Docker BuildKit and other optimizations for faster builds

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="nborgers/zeek"
TAG="latest"
BUILDKIT_ENABLED=1
PARALLEL_BUILDS=1

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --tag TAG           Docker tag (default: latest)"
    echo "  -i, --image NAME        Image name (default: nborgers/zeek)"
    echo "  -p, --parallel N        Number of parallel builds (default: 1)"
    echo "  -u, --ultra             Use ultra-optimized Dockerfile"
    echo "  -c, --cache             Enable BuildKit cache"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                      # Build with default settings"
    echo "  $0 -t v1.0.0           # Build with specific tag"
    echo "  $0 -u -c               # Build with ultra optimizations and cache"
    echo "  $0 -p 2                # Build with 2 parallel processes"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -i|--image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL_BUILDS="$2"
            shift 2
            ;;
        -u|--ultra)
            USE_ULTRA=1
            shift
            ;;
        -c|--cache)
            USE_CACHE=1
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Enable BuildKit if requested
if [[ $BUILDKIT_ENABLED -eq 1 ]]; then
    export DOCKER_BUILDKIT=1
    print_status "Docker BuildKit enabled"
fi

# Determine which Dockerfile to use
if [[ $USE_ULTRA -eq 1 ]]; then
    DOCKERFILE="Dockerfile.ultra-optimized"
    print_status "Using ultra-optimized Dockerfile"
else
    DOCKERFILE="Dockerfile"
    print_status "Using optimized Dockerfile"
fi

# Check if Dockerfile exists
if [[ ! -f "$DOCKERFILE" ]]; then
    print_error "Dockerfile '$DOCKERFILE' not found"
    exit 1
fi

# Build arguments
BUILD_ARGS=(
    "--file" "$DOCKERFILE"
    "--tag" "${IMAGE_NAME}:${TAG}"
    "--progress=plain"
)

# Add cache options if requested
if [[ $USE_CACHE -eq 1 ]]; then
    BUILD_ARGS+=(
        "--build-arg" "BUILDKIT_INLINE_CACHE=1"
        "--cache-from" "${IMAGE_NAME}:${TAG}"
    )
    print_status "Build cache enabled"
fi

# Add parallel build option
if [[ $PARALLEL_BUILDS -gt 1 ]]; then
    BUILD_ARGS+=("--build-arg" "PARALLEL_BUILDS=${PARALLEL_BUILDS}")
    print_status "Parallel builds: $PARALLEL_BUILDS"
fi

# Show build configuration
print_status "Build configuration:"
echo "  Image: ${IMAGE_NAME}:${TAG}"
echo "  Dockerfile: $DOCKERFILE"
echo "  BuildKit: $([ $BUILDKIT_ENABLED -eq 1 ] && echo "Enabled" || echo "Disabled")"
echo "  Cache: $([ $USE_CACHE -eq 1 ] && echo "Enabled" || echo "Disabled")"
echo "  Parallel: $PARALLEL_BUILDS"

# Start build
print_status "Starting Docker build..."
echo "Command: docker build ${BUILD_ARGS[@]} ."
echo ""

# Record start time
START_TIME=$(date +%s)

# Run the build
if docker build "${BUILD_ARGS[@]}" .; then
    # Calculate build time
    END_TIME=$(date +%s)
    BUILD_TIME=$((END_TIME - START_TIME))
    
    print_success "Build completed successfully!"
    print_status "Build time: ${BUILD_TIME} seconds"
    
    # Show image information
    print_status "Image information:"
    docker images "${IMAGE_NAME}:${TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
    
    # Show image size
    IMAGE_SIZE=$(docker images "${IMAGE_NAME}:${TAG}" --format "{{.Size}}")
    print_status "Final image size: $IMAGE_SIZE"
    
    # Optional: run quick test
    if command -v make >/dev/null 2>&1; then
        read -p "Run quick test on the built image? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Running quick test..."
            make test-quick
        fi
    fi
    
else
    print_error "Build failed!"
    exit 1
fi 