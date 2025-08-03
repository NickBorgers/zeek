# Zeek Docker Image Test Suite

This directory contains comprehensive tests for the Zeek Docker image to ensure it builds correctly, runs properly, and generates logs as expected.

## Test Scripts

### 1. `test-build-and-run.sh` - Comprehensive Bash Tests
**Duration:** ~2-3 minutes  
**Purpose:** Full integration testing with traffic generation

**Tests:**
- Docker image build
- Zeek installation verification
- Plugin availability check
- Container execution
- Traffic generation (ping, HTTP, DNS)
- Log file generation and validation
- Protocol-specific monitoring
- Container health checks
- Configuration syntax validation

**Usage:**
```bash
./tests/test-build-and-run.sh
```

### 2. `quick-test.sh` - Quick Validation Tests
**Duration:** ~30 seconds  
**Purpose:** Fast validation for development

**Tests:**
- Docker image build
- Zeek installation
- Configuration files existence
- Configuration syntax
- Basic container execution
- Simple log generation
- Container health

**Usage:**
```bash
./tests/quick-test.sh
```

### 3. `test_zeek_docker.py` - Python Test Suite
**Duration:** ~1-2 minutes  
**Purpose:** Advanced testing with JSON log validation

**Tests:**
- Docker image build (using Docker SDK)
- Zeek installation verification
- Configuration file validation
- Configuration syntax checking
- Container execution and health
- Log generation verification
- JSON log parsing and validation
- Memory usage monitoring
- Error detection in container logs

**Requirements:**
```bash
pip install -r tests/requirements.txt
```

**Usage:**
```bash
python3 tests/test_zeek_docker.py
```

## Using the Makefile

The repository includes a `Makefile` with convenient targets:

```bash
# Show all available targets
make help

# Build the image
make build

# Run quick tests
make test-quick

# Run comprehensive tests
make test

# Run Python tests
make test-python

# Run all tests
make test-all

# Clean up test artifacts
make clean

# Development workflow (clean, build, test)
make dev

# Production build (clean, build, all tests)
make prod
```

## Test Output

### Expected Log Files
The tests verify that the following log files are generated:

- `conn.log` - Connection records
- `dns.log` - DNS queries and responses
- `http.log` - HTTP traffic
- `ssl.log` - SSL/TLS connections
- `dhcp.log` - DHCP traffic (if available)
- `arp.log` - ARP traffic (if available)
- `mdns.log` - mDNS traffic (if available)
- And other protocol-specific logs

### JSON Log Validation
The Python test suite validates that:
- Log files contain valid JSON
- JSON structure is consistent
- Required fields are present
- No malformed entries exist

## Test Environment

### Prerequisites
- Docker installed and running
- Python 3.6+ (for Python tests)
- Internet connection (for traffic generation)

### Test Network
Tests create isolated Docker networks to:
- Prevent interference with host network
- Generate controlled test traffic
- Ensure clean test environment

### Cleanup
All tests include automatic cleanup:
- Stop and remove test containers
- Remove test images
- Clean up log directories
- Remove test networks

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Ensure scripts are executable
   chmod +x tests/*.sh tests/*.py
   ```

2. **Docker Not Running**
   ```bash
   # Start Docker service
   sudo systemctl start docker
   ```

3. **Python Dependencies Missing**
   ```bash
   # Install dependencies
   pip install -r tests/requirements.txt
   ```

4. **Container Fails to Start**
   ```bash
   # Check Docker logs
   docker logs <container-name>
   
   # Check available interfaces
   docker run --rm nborgers/zeek:latest ip link show
   ```

5. **No Logs Generated**
   ```bash
   # Check if traffic is being generated
   docker exec <container-name> tcpdump -i any -c 10
   
   # Verify interface configuration
   docker exec <container-name> zeek -i <interface> -C /opt/zeek/etc/zeek-config.zeek
   ```

### Debug Mode

For debugging, you can run tests with verbose output:

```bash
# Bash tests with debug
bash -x tests/quick-test.sh

# Python tests with debug
python3 -v tests/test_zeek_docker.py
```

## Continuous Integration

These tests are designed to work in CI/CD environments:

- **GitHub Actions:** Tests run automatically on pull requests
- **Docker Hub:** Tests run before image publication
- **Local Development:** Quick validation during development

## Test Coverage

The test suite covers:

- ✅ **Build Process:** Multi-stage Docker build
- ✅ **Installation:** Zeek and plugin installation
- ✅ **Configuration:** Syntax and file validation
- ✅ **Execution:** Container startup and health
- ✅ **Functionality:** Log generation and protocol monitoring
- ✅ **Performance:** Memory usage and resource consumption
- ✅ **Integration:** End-to-end workflow validation

## Contributing

When adding new features to the Zeek Docker image:

1. **Add corresponding tests** to the appropriate test script
2. **Update test documentation** if needed
3. **Ensure all tests pass** before submitting PR
4. **Add new test cases** for any new protocols or features

## Test Results

Successful test execution should show:

```
[SUCCESS] Docker image built successfully
[SUCCESS] Zeek is properly installed
[SUCCESS] Configuration files exist
[SUCCESS] Configuration syntax is valid
[SUCCESS] Container is running
[SUCCESS] Log files are generated
[SUCCESS] Container is healthy
[SUCCESS] All tests completed successfully!
```

If any tests fail, the output will indicate which specific test failed and provide debugging information. 