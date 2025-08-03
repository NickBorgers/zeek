#!/usr/bin/env python3
"""
Python test script for Zeek Docker image
Provides advanced testing capabilities including JSON log parsing and validation
"""

import json
import subprocess
import time
import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import docker
from docker.errors import DockerException, ImageNotFound, ContainerError

class ZeekDockerTester:
    """Test suite for Zeek Docker image"""
    
    def __init__(self):
        self.client = docker.from_env()
        self.image_name = "zeek-test"
        self.container_name = "zeek-test-container"
        self.log_dir = Path("./test-logs")
        self.test_results = {}
        
    def print_status(self, message: str):
        """Print status message with color"""
        print(f"\033[94m[INFO]\033[0m {message}")
        
    def print_success(self, message: str):
        """Print success message with color"""
        print(f"\033[92m[SUCCESS]\033[0m {message}")
        
    def print_warning(self, message: str):
        """Print warning message with color"""
        print(f"\033[93m[WARNING]\033[0m {message}")
        
    def print_error(self, message: str):
        """Print error message with color"""
        print(f"\033[91m[ERROR]\033[0m {message}")
        
    def cleanup(self):
        """Clean up test resources"""
        self.print_status("Cleaning up test resources...")
        
        try:
            # Stop and remove container
            container = self.client.containers.get(self.container_name)
            container.stop(timeout=10)
            container.remove()
        except:
            pass
            
        try:
            # Remove image
            image = self.client.images.get(self.image_name)
            image.remove(force=True)
        except:
            pass
            
        # Remove log directory
        if self.log_dir.exists():
            shutil.rmtree(self.log_dir)
            
        self.print_success("Cleanup completed")
        
    def test_build_image(self) -> bool:
        """Test building the Docker image"""
        self.print_status("Building Docker image...")
        
        try:
            # Build image
            image, logs = self.client.images.build(
                path=".",
                tag=self.image_name,
                rm=True
            )
            self.print_success("Docker image built successfully")
            self.test_results['build'] = True
            return True
        except Exception as e:
            self.print_error(f"Failed to build Docker image: {e}")
            self.test_results['build'] = False
            return False
            
    def test_zeek_installation(self) -> bool:
        """Test Zeek installation in the image"""
        self.print_status("Testing Zeek installation...")
        
        try:
            container = self.client.containers.run(
                self.image_name,
                command="zeek --version",
                remove=True,
                detach=False
            )
            
            if container.decode('utf-8').strip():
                self.print_success("Zeek is properly installed")
                self.test_results['zeek_installation'] = True
                return True
            else:
                self.print_error("Zeek installation failed")
                self.test_results['zeek_installation'] = False
                return False
                
        except Exception as e:
            self.print_error(f"Failed to test Zeek installation: {e}")
            self.test_results['zeek_installation'] = False
            return False
            
    def test_configuration_files(self) -> bool:
        """Test that configuration files exist"""
        self.print_status("Testing configuration files...")
        
        try:
            container = self.client.containers.run(
                self.image_name,
                command="test -f /opt/zeek/etc/zeek-config.zeek && test -f /opt/zeek/share/zeek/site/local.zeek",
                remove=True,
                detach=False
            )
            
            self.print_success("Configuration files exist")
            self.test_results['config_files'] = True
            return True
            
        except Exception as e:
            self.print_error(f"Configuration files missing: {e}")
            self.test_results['config_files'] = False
            return False
            
    def test_configuration_syntax(self) -> bool:
        """Test configuration syntax"""
        self.print_status("Testing configuration syntax...")
        
        try:
            # Test main configuration
            container = self.client.containers.run(
                self.image_name,
                command="zeek -C /opt/zeek/etc/zeek-config.zeek --parse-only",
                remove=True,
                detach=False
            )
            
            # Test local configuration
            container = self.client.containers.run(
                self.image_name,
                command="zeek -C /opt/zeek/share/zeek/site/local.zeek --parse-only",
                remove=True,
                detach=False
            )
            
            self.print_success("Configuration syntax is valid")
            self.test_results['config_syntax'] = True
            return True
            
        except Exception as e:
            self.print_error(f"Configuration syntax error: {e}")
            self.test_results['config_syntax'] = False
            return False
            
    def test_container_run(self) -> bool:
        """Test running the container"""
        self.print_status("Testing container execution...")
        
        try:
            # Create log directory
            self.log_dir.mkdir(exist_ok=True)
            
            # Run container
            container = self.client.containers.run(
                self.image_name,
                command="zeek -i lo -C /opt/zeek/etc/zeek-config.zeek",
                name=self.container_name,
                detach=True,
                volumes={
                    str(self.log_dir.absolute()): {
                        'bind': '/opt/zeek/logs',
                        'mode': 'rw'
                    }
                },
                cap_add=['NET_ADMIN', 'NET_RAW']
            )
            
            # Wait for container to start
            time.sleep(5)
            
            # Check if container is running
            container.reload()
            if container.status == 'running':
                self.print_success("Container is running")
                self.test_results['container_run'] = True
                return True
            else:
                self.print_error("Container failed to start")
                logs = container.logs().decode('utf-8')
                self.print_error(f"Container logs: {logs}")
                self.test_results['container_run'] = False
                return False
                
        except Exception as e:
            self.print_error(f"Failed to run container: {e}")
            self.test_results['container_run'] = False
            return False
            
    def test_log_generation(self) -> bool:
        """Test log generation"""
        self.print_status("Testing log generation...")
        
        try:
            # Generate some traffic
            container = self.client.containers.get(self.container_name)
            container.exec_run("ping -c 3 8.8.8.8")
            
            # Wait for processing
            time.sleep(10)
            
            # Check for log files
            log_files = list(self.log_dir.glob("*.log"))
            
            if log_files:
                self.print_success(f"Found {len(log_files)} log files")
                
                # Check specific log files
                expected_logs = ['conn.log', 'dns.log', 'http.log']
                found_logs = []
                
                for log_file in log_files:
                    if log_file.name in expected_logs:
                        found_logs.append(log_file.name)
                        
                        # Check if log has content
                        if log_file.stat().st_size > 0:
                            self.print_success(f"Log file {log_file.name} contains data")
                            
                            # Try to parse JSON if it's a JSON log
                            try:
                                with open(log_file, 'r') as f:
                                    first_line = f.readline().strip()
                                    if first_line:
                                        json.loads(first_line)
                                        self.print_success(f"Log file {log_file.name} contains valid JSON")
                            except json.JSONDecodeError:
                                self.print_warning(f"Log file {log_file.name} is not JSON format")
                        else:
                            self.print_warning(f"Log file {log_file.name} is empty")
                            
                self.print_status(f"Found expected logs: {found_logs}")
                self.test_results['log_generation'] = True
                return True
            else:
                self.print_error("No log files generated")
                self.test_results['log_generation'] = False
                return False
                
        except Exception as e:
            self.print_error(f"Failed to test log generation: {e}")
            self.test_results['log_generation'] = False
            return False
            
    def test_json_log_parsing(self) -> bool:
        """Test parsing JSON logs"""
        self.print_status("Testing JSON log parsing...")
        
        try:
            # Find JSON log files
            json_logs = []
            for log_file in self.log_dir.glob("*.log"):
                try:
                    with open(log_file, 'r') as f:
                        first_line = f.readline().strip()
                        if first_line:
                            json.loads(first_line)
                            json_logs.append(log_file)
                except (json.JSONDecodeError, FileNotFoundError):
                    continue
                    
            if json_logs:
                self.print_success(f"Found {len(json_logs)} JSON log files")
                
                # Parse and validate log structure
                for log_file in json_logs:
                    with open(log_file, 'r') as f:
                        for i, line in enumerate(f):
                            if i >= 5:  # Check first 5 lines
                                break
                            try:
                                log_entry = json.loads(line.strip())
                                if isinstance(log_entry, dict):
                                    self.print_success(f"Log file {log_file.name} has valid JSON structure")
                                    break
                            except json.JSONDecodeError:
                                continue
                                
                self.test_results['json_parsing'] = True
                return True
            else:
                self.print_warning("No JSON log files found")
                self.test_results['json_parsing'] = False
                return False
                
        except Exception as e:
            self.print_error(f"Failed to test JSON parsing: {e}")
            self.test_results['json_parsing'] = False
            return False
            
    def test_container_health(self) -> bool:
        """Test container health"""
        self.print_status("Testing container health...")
        
        try:
            container = self.client.containers.get(self.container_name)
            container.reload()
            
            if container.status == 'running':
                # Check memory usage
                stats = container.stats(stream=False)
                memory_usage = stats['memory_stats']['usage'] / 1024 / 1024  # MB
                
                self.print_success(f"Container is healthy (Memory: {memory_usage:.1f} MB)")
                
                # Check for errors in logs
                logs = container.logs().decode('utf-8')
                error_count = logs.lower().count('error')
                
                if error_count == 0:
                    self.print_success("No errors found in container logs")
                else:
                    self.print_warning(f"Found {error_count} potential errors in container logs")
                    
                self.test_results['container_health'] = True
                return True
            else:
                self.print_error(f"Container is not running (status: {container.status})")
                self.test_results['container_health'] = False
                return False
                
        except Exception as e:
            self.print_error(f"Failed to test container health: {e}")
            self.test_results['container_health'] = False
            return False
            
    def run_all_tests(self) -> bool:
        """Run all tests"""
        self.print_status("Starting comprehensive Zeek Docker image tests...")
        
        tests = [
            self.test_build_image,
            self.test_zeek_installation,
            self.test_configuration_files,
            self.test_configuration_syntax,
            self.test_container_run,
            self.test_log_generation,
            self.test_json_log_parsing,
            self.test_container_health
        ]
        
        all_passed = True
        for test in tests:
            if not test():
                all_passed = False
                
        # Print summary
        self.print_summary()
        
        return all_passed
        
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*50)
        self.print_status("TEST SUMMARY")
        print("="*50)
        
        for test_name, result in self.test_results.items():
            status = "PASS" if result else "FAIL"
            color = "\033[92m" if result else "\033[91m"
            print(f"{color}{status}\033[0m - {test_name}")
            
        passed = sum(self.test_results.values())
        total = len(self.test_results)
        
        print(f"\nOverall: {passed}/{total} tests passed")
        
        if passed == total:
            self.print_success("All tests passed! Zeek Docker image is ready for production.")
        else:
            self.print_error("Some tests failed. Please review the output above.")
            
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

def main():
    """Main function"""
    try:
        with ZeekDockerTester() as tester:
            success = tester.run_all_tests()
            sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\033[93m[WARNING]\033[0m Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 