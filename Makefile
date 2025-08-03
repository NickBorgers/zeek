# Makefile for Zeek Docker Image
# Provides convenient targets for building, testing, and running

.PHONY: help build test test-quick test-python clean run logs

# Default target
help:
	@echo "Zeek Docker Image - Available targets:"
	@echo ""
	@echo "  build        - Build the Docker image"
	@echo "  test         - Run comprehensive tests (bash)"
	@echo "  test-quick   - Run quick tests (bash)"
	@echo "  test-python  - Run Python-based tests"
	@echo "  clean        - Clean up test artifacts"
	@echo "  run          - Run the container"
	@echo "  logs         - Show container logs"
	@echo "  stop         - Stop the container"
	@echo "  shell        - Open shell in running container"
	@echo ""

# Build the Docker image
build:
	@echo "Building Zeek Docker image..."
	docker build -t nborgers/zeek:latest .

# Run comprehensive tests
test:
	@echo "Running comprehensive tests..."
	@chmod +x tests/test-build-and-run.sh
	@./tests/test-build-and-run.sh

# Run quick tests
test-quick:
	@echo "Running quick tests..."
	@chmod +x tests/quick-test.sh
	@./tests/quick-test.sh

# Run Python tests
test-python:
	@echo "Running Python tests..."
	@echo "Installing Python dependencies..."
	pip install -r tests/requirements.txt
	@echo "Running Python test suite..."
	python3 tests/test_zeek_docker.py

# Clean up test artifacts
clean:
	@echo "Cleaning up test artifacts..."
	@rm -rf test-logs quick-test-logs
	@docker stop zeek-test-container zeek-quick-test-container 2>/dev/null || true
	@docker rm zeek-test-container zeek-quick-test-container 2>/dev/null || true
	@docker rmi zeek-test zeek-quick-test 2>/dev/null || true
	@echo "Cleanup completed"

# Run the container
run:
	@echo "Running Zeek container..."
	@mkdir -p logs
	docker run -d \
		--name zeek-monitor \
		--network host \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		-v $(PWD)/logs:/opt/zeek/logs \
		nborgers/zeek:latest

# Show container logs
logs:
	@docker logs -f zeek-monitor

# Stop the container
stop:
	@echo "Stopping Zeek container..."
	@docker stop zeek-monitor 2>/dev/null || true
	@docker rm zeek-monitor 2>/dev/null || true

# Open shell in running container
shell:
	@docker exec -it zeek-monitor /bin/bash

# Install Python dependencies for testing
install-test-deps:
	@echo "Installing Python test dependencies..."
	pip install -r tests/requirements.txt

# Run all tests
test-all: test-quick test-python
	@echo "All tests completed"

# Build and test
build-test: build test-quick
	@echo "Build and test completed"

# Development workflow
dev: clean build test-quick
	@echo "Development workflow completed"

# Production build
prod: clean build test-all
	@echo "Production build completed" 