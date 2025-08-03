#!/bin/bash

# Quick test script for Zeek Docker image
# This script performs basic validation without extensive traffic generation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="zeek-quick-test"
CONTAINER_NAME="zeek-quick-test-container"
LOG_DIR="./quick-test-logs"

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

# Function to cleanup
cleanup() {
    print_status "Cleaning up..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
    docker rmi $IMAGE_NAME 2>/dev/null || true
    rm -rf $LOG_DIR 2>/dev/null || true
}

# Set up trap to cleanup on exit
trap cleanup EXIT

print_status "Starting quick test of Zeek Docker image..."

# Test 1: Build the image
print_status "Building Docker image..."
if docker build -t $IMAGE_NAME .; then
    print_success "Image built successfully"
else
    print_error "Failed to build image"
    exit 1
fi

# Test 2: Verify Zeek installation
print_status "Verifying Zeek installation..."
if docker run --rm $IMAGE_NAME zeek --version; then
    print_success "Zeek is properly installed"
else
    print_error "Zeek installation failed"
    exit 1
fi

# Test 3: Check configuration files
print_status "Checking configuration files..."
if docker run --rm $IMAGE_NAME test -f /opt/zeek/etc/zeek-config.zeek; then
    print_success "Configuration files exist"
else
    print_error "Configuration files missing"
    exit 1
fi

# Test 4: Test configuration syntax
print_status "Testing configuration syntax..."
if docker run --rm $IMAGE_NAME zeek -C /opt/zeek/etc/zeek-config.zeek --parse-only; then
    print_success "Configuration syntax is valid"
else
    print_error "Configuration has syntax errors"
    exit 1
fi

# Test 5: Run container and generate basic logs
print_status "Running container with basic traffic..."
mkdir -p $LOG_DIR

# Run container in background
docker run -d \
    --name $CONTAINER_NAME \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v $(pwd)/$LOG_DIR:/opt/zeek/logs \
    $IMAGE_NAME \
    zeek -i lo -C /opt/zeek/etc/zeek-config.zeek

# Wait for container to start
sleep 3

# Check if container is running
if docker ps | grep -q $CONTAINER_NAME; then
    print_success "Container is running"
else
    print_error "Container failed to start"
    docker logs $CONTAINER_NAME
    exit 1
fi

# Generate some basic traffic
print_status "Generating basic test traffic..."
docker exec $CONTAINER_NAME ping -c 3 8.8.8.8 > /dev/null 2>&1 || true

# Wait for processing
sleep 5

# Test 6: Check for log files
print_status "Checking for log files..."
if [ -f "$LOG_DIR/conn.log" ]; then
    print_success "Connection log generated"
    if [ -s "$LOG_DIR/conn.log" ]; then
        print_success "Connection log contains data"
        print_status "Sample log entry:"
        head -1 "$LOG_DIR/conn.log" | sed 's/^/  /'
    else
        print_warning "Connection log is empty"
    fi
else
    print_warning "Connection log not found"
fi

# Check for any log files
total_logs=$(find $LOG_DIR -name "*.log" 2>/dev/null | wc -l)
if [ $total_logs -gt 0 ]; then
    print_success "Found $total_logs log files"
    print_status "Available logs:"
    find $LOG_DIR -name "*.log" 2>/dev/null | sed 's/^/  /'
else
    print_warning "No log files found"
fi

# Test 7: Check container health
print_status "Checking container health..."
if docker ps | grep -q $CONTAINER_NAME; then
    print_success "Container is healthy"
else
    print_error "Container stopped unexpectedly"
    docker logs $CONTAINER_NAME
    exit 1
fi

print_success "Quick test completed successfully!"
print_status "Test logs available in: $LOG_DIR" 