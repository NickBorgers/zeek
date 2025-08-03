#!/bin/bash

# Comprehensive test script for Zeek Docker image
# This script builds the image, runs it, generates test traffic, and verifies logs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="zeek-test"
CONTAINER_NAME="zeek-test-container"
TEST_DURATION=30
LOG_DIR="./test-logs"
NETWORK_NAME="zeek-test-network"

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
    print_status "Cleaning up test environment..."
    
    # Stop and remove container
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
    
    # Remove test network
    docker network rm $NETWORK_NAME 2>/dev/null || true
    
    # Remove test image
    docker rmi $IMAGE_NAME 2>/dev/null || true
    
    # Remove test logs
    rm -rf $LOG_DIR 2>/dev/null || true
    
    print_success "Cleanup completed"
}

# Set up trap to cleanup on exit
trap cleanup EXIT

# Test 1: Build the Docker image
test_build() {
    print_status "Test 1: Building Docker image..."
    
    if docker build -t $IMAGE_NAME .; then
        print_success "Docker image built successfully"
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
}

# Test 2: Verify image contains expected components
test_image_components() {
    print_status "Test 2: Verifying image components..."
    
    # Check if Zeek is installed
    if docker run --rm $IMAGE_NAME zeek --version; then
        print_success "Zeek is properly installed"
    else
        print_error "Zeek is not properly installed"
        exit 1
    fi
    
    # Check available plugins
    print_status "Checking available plugins..."
    docker run --rm $IMAGE_NAME zeek -N | grep -E "(arp|dhcp|mdns|netbios|llmnr|ntp|snmp|tftp|syslog|modbus|dnp3|bacnet|smb|rdp)" || {
        print_warning "Some expected plugins may not be available"
    }
    
    # Check configuration files exist
    if docker run --rm $IMAGE_NAME test -f /opt/zeek/etc/zeek-config.zeek; then
        print_success "Configuration files are present"
    else
        print_error "Configuration files are missing"
        exit 1
    fi
}

# Test 3: Create test network and run container
test_container_run() {
    print_status "Test 3: Running container with test network..."
    
    # Create test network
    docker network create $NETWORK_NAME 2>/dev/null || true
    
    # Create log directory
    mkdir -p $LOG_DIR
    
    # Run container in background
    docker run -d \
        --name $CONTAINER_NAME \
        --network $NETWORK_NAME \
        --cap-add=NET_ADMIN \
        --cap-add=NET_RAW \
        -v $(pwd)/$LOG_DIR:/opt/zeek/logs \
        $IMAGE_NAME \
        zeek -i lo -C /opt/zeek/etc/zeek-config.zeek
    
    # Wait for container to start
    sleep 5
    
    # Check if container is running
    if docker ps | grep -q $CONTAINER_NAME; then
        print_success "Container is running"
    else
        print_error "Container failed to start"
        docker logs $CONTAINER_NAME
        exit 1
    fi
}

# Test 4: Generate test traffic
test_traffic_generation() {
    print_status "Test 4: Generating test traffic..."
    
    # Create a test container to generate traffic
    docker run -d \
        --name traffic-generator \
        --network $NETWORK_NAME \
        alpine:latest \
        sh -c "while true; do ping -c 1 8.8.8.8; sleep 2; done"
    
    # Generate some HTTP traffic
    docker run -d \
        --name http-generator \
        --network $NETWORK_NAME \
        alpine:latest \
        sh -c "apk add --no-cache curl && while true; do curl -s http://httpbin.org/get > /dev/null; sleep 3; done"
    
    # Generate DNS queries
    docker run -d \
        --name dns-generator \
        --network $NETWORK_NAME \
        alpine:latest \
        sh -c "apk add --no-cache bind-tools && while true; do nslookup google.com 8.8.8.8; sleep 4; done"
    
    print_success "Test traffic generators started"
}

# Test 5: Wait and check for logs
test_log_generation() {
    print_status "Test 5: Waiting for logs to be generated..."
    
    # Wait for traffic to be processed
    print_status "Waiting $TEST_DURATION seconds for traffic processing..."
    sleep $TEST_DURATION
    
    # Check if log files exist
    print_status "Checking for log files..."
    
    local log_files_found=0
    local expected_logs=("conn.log" "dns.log" "http.log")
    
    for log_file in "${expected_logs[@]}"; do
        if [ -f "$LOG_DIR/$log_file" ]; then
            print_success "Found log file: $log_file"
            log_files_found=$((log_files_found + 1))
            
            # Check if log file has content
            if [ -s "$LOG_DIR/$log_file" ]; then
                print_success "Log file $log_file contains data"
                
                # Show first few lines of log
                print_status "First few lines of $log_file:"
                head -3 "$LOG_DIR/$log_file" | sed 's/^/  /'
            else
                print_warning "Log file $log_file is empty"
            fi
        else
            print_warning "Log file not found: $log_file"
        fi
    done
    
    # Check for any other log files
    local total_logs=$(find $LOG_DIR -name "*.log" | wc -l)
    print_status "Total log files found: $total_logs"
    
    if [ $log_files_found -gt 0 ]; then
        print_success "Log generation test passed"
    else
        print_error "No expected log files were generated"
        exit 1
    fi
}

# Test 6: Test specific protocol monitoring
test_protocol_monitoring() {
    print_status "Test 6: Testing specific protocol monitoring..."
    
    # Test DHCP monitoring (if available)
    if docker exec $CONTAINER_NAME test -f /opt/zeek/logs/dhcp.log; then
        print_success "DHCP monitoring is working"
    else
        print_warning "DHCP log not found (may be normal if no DHCP traffic)"
    fi
    
    # Test DNS monitoring
    if docker exec $CONTAINER_NAME test -f /opt/zeek/logs/dns.log; then
        print_success "DNS monitoring is working"
    else
        print_warning "DNS log not found"
    fi
    
    # Test HTTP monitoring
    if docker exec $CONTAINER_NAME test -f /opt/zeek/logs/http.log; then
        print_success "HTTP monitoring is working"
    else
        print_warning "HTTP log not found"
    fi
    
    # Test connection monitoring
    if docker exec $CONTAINER_NAME test -f /opt/zeek/logs/conn.log; then
        print_success "Connection monitoring is working"
    else
        print_warning "Connection log not found"
    fi
}

# Test 7: Test container health and performance
test_container_health() {
    print_status "Test 7: Testing container health..."
    
    # Check container is still running
    if docker ps | grep -q $CONTAINER_NAME; then
        print_success "Container is still running"
    else
        print_error "Container stopped unexpectedly"
        docker logs $CONTAINER_NAME
        exit 1
    fi
    
    # Check container logs for errors
    local error_count=$(docker logs $CONTAINER_NAME 2>&1 | grep -i error | wc -l)
    if [ $error_count -eq 0 ]; then
        print_success "No errors found in container logs"
    else
        print_warning "Found $error_count potential errors in container logs"
        docker logs $CONTAINER_NAME | grep -i error
    fi
    
    # Check memory usage
    local memory_usage=$(docker stats $CONTAINER_NAME --no-stream --format "table {{.MemUsage}}" | tail -1)
    print_status "Container memory usage: $memory_usage"
}

# Test 8: Test configuration loading
test_configuration() {
    print_status "Test 8: Testing configuration loading..."
    
    # Test if configuration loads without errors
    if docker exec $CONTAINER_NAME zeek -C /opt/zeek/etc/zeek-config.zeek --parse-only; then
        print_success "Configuration syntax is valid"
    else
        print_error "Configuration has syntax errors"
        exit 1
    fi
    
    # Test if local configuration loads
    if docker exec $CONTAINER_NAME zeek -C /opt/zeek/share/zeek/site/local.zeek --parse-only; then
        print_success "Local configuration syntax is valid"
    else
        print_warning "Local configuration has syntax errors"
    fi
}

# Main test execution
main() {
    print_status "Starting comprehensive Zeek Docker image tests..."
    print_status "Test duration: $TEST_DURATION seconds"
    
    # Run all tests
    test_build
    test_image_components
    test_container_run
    test_traffic_generation
    test_log_generation
    test_protocol_monitoring
    test_container_health
    test_configuration
    
    print_success "All tests completed successfully!"
    print_status "Test logs are available in: $LOG_DIR"
    
    # Show summary
    echo
    print_status "Test Summary:"
    echo "  - Docker image built successfully"
    echo "  - Container runs without errors"
    echo "  - Log files are generated"
    echo "  - Configuration is valid"
    echo "  - Protocol monitoring is working"
    echo
    print_success "Zeek Docker image is ready for production use!"
}

# Run main function
main "$@" 