# Comprehensive Zeek Docker Image

A feature-rich Docker image for Zeek (formerly Bro) network security monitoring with comprehensive plugin support for monitoring broadcast traffic, mDNS, DHCP, ARP, and other local network communications.

## Features

This Zeek Docker image includes support for the following protocols and plugins:

### Core Network Protocols
- **ARP** - Address Resolution Protocol monitoring
- **DHCP** - Dynamic Host Configuration Protocol
- **mDNS** - Multicast DNS (Bonjour/Avahi)
- **NetBIOS** - Network Basic Input/Output System
- **LLMNR** - Link-Local Multicast Name Resolution
- **NTP** - Network Time Protocol
- **SNMP** - Simple Network Management Protocol
- **TFTP** - Trivial File Transfer Protocol
- **Syslog** - System logging protocol

### Industrial Protocols
- **Modbus** - Industrial control system protocol
- **DNP3** - Distributed Network Protocol 3
- **BACnet** - Building Automation and Control Networks

### Windows/Enterprise Protocols
- **SMB** - Server Message Block
- **RDP** - Remote Desktop Protocol

### Additional Features
- Multi-architecture support (AMD64, ARM64)
- JSON logging for better integration
- Custom broadcast traffic monitoring
- Comprehensive logging configuration
- Security scanning with Trivy and Snyk
- Automated CI/CD pipeline

## Quick Start

### Pull and Run
```bash
# Pull the latest image
docker pull nborgers/zeek:latest

# Run with default configuration
docker run --rm -it --network host nborgers/zeek:latest

# Run with custom interface
docker run --rm -it --network host nborgers/zeek:latest zeek -i eth0 -C
```

### With Persistent Logs
```bash
# Create a directory for logs
mkdir -p /opt/zeek-logs

# Run with volume mount for logs
docker run --rm -it \
  --network host \
  -v /opt/zeek-logs:/opt/zeek/logs \
  nborgers/zeek:latest
```

### With Custom Configuration
```bash
# Create custom configuration
cat > custom-config.zeek << EOF
@load /opt/zeek/etc/zeek-config.zeek
# Add your custom rules here
EOF

# Run with custom configuration
docker run --rm -it \
  --network host \
  -v $(pwd)/custom-config.zeek:/opt/zeek/etc/custom-config.zeek \
  -v /opt/zeek-logs:/opt/zeek/logs \
  nborgers/zeek:latest zeek -C /opt/zeek/etc/custom-config.zeek
```

## Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  zeek:
    image: nborgers/zeek:latest
    container_name: zeek-monitor
    network_mode: host
    volumes:
      - ./logs:/opt/zeek/logs
      - ./config:/opt/zeek/etc
    environment:
      - ZEEK_LOG_DIR=/opt/zeek/logs
    restart: unless-stopped
    command: zeek -i eth0 -C /opt/zeek/etc/zeek-config.zeek
    cap_add:
      - NET_ADMIN
      - NET_RAW
    security_opt:
      - no-new-privileges:true
```

Run with:
```bash
docker-compose up -d
```

## Configuration

### Default Configuration
The image includes a comprehensive configuration file (`zeek-config.zeek`) that:
- Loads all available plugins
- Enables monitoring for broadcast traffic
- Configures JSON logging
- Sets up custom event handlers for each protocol

### Custom Configuration
You can override the default configuration by mounting your own Zeek scripts:

```bash
docker run --rm -it \
  --network host \
  -v /path/to/your/config.zeek:/opt/zeek/etc/custom-config.zeek \
  nborgers/zeek:latest zeek -C /opt/zeek/etc/custom-config.zeek
```

### Environment Variables
- `ZEEK_LOG_DIR` - Directory for log files (default: `/opt/zeek/logs`)
- `ZEEK_CONFIG_FILE` - Path to configuration file (default: `/opt/zeek/etc/zeek-config.zeek`)

## Monitoring Specific Protocols

### DHCP Monitoring
The image automatically monitors DHCP traffic and logs:
- DHCP requests and responses
- IP address assignments
- DHCP option information

### mDNS Monitoring
Monitors multicast DNS traffic for:
- Service discovery queries
- Device announcements
- Bonjour/Avahi traffic

### ARP Monitoring
Tracks ARP requests and responses for:
- MAC address resolution
- Potential ARP spoofing detection
- Network topology mapping

### Broadcast Traffic
Custom monitoring for broadcast and multicast traffic:
- General broadcast traffic (255.255.255.255)
- Multicast traffic (224.0.0.1, 224.0.0.251)
- Protocol-specific broadcast events

## Log Output

The image generates several log files in JSON format:

- `conn.log` - Connection records
- `dhcp.log` - DHCP traffic
- `mdns.log` - mDNS traffic
- `arp.log` - ARP traffic
- `broadcast.log` - Custom broadcast monitoring
- `dns.log` - DNS queries
- `http.log` - HTTP traffic
- `ssl.log` - SSL/TLS connections
- And many more protocol-specific logs

### Example Log Entry
```json
{
  "ts": "2024-01-15T10:30:00.000000Z",
  "uid": "C1234567890",
  "src_ip": "192.168.1.100",
  "dst_ip": "255.255.255.255",
  "protocol": "DHCP",
  "service": "dhcp",
  "message": "DHCP DISCOVER from 192.168.1.100",
  "severity": "info"
}
```

## Building from Source

### Prerequisites
- Docker
- Git

### Build Steps
```bash
# Clone the repository
git clone https://github.com/nborgers/zeek.git
cd zeek

# Build the image
docker build -t nborgers/zeek:latest .

# Build with specific Zeek version
docker build --build-arg ZEEK_VERSION=6.0.0 -t nborgers/zeek:6.0.0 .
```

## CI/CD Pipeline

This repository includes a GitHub Actions workflow that:
- Builds multi-architecture Docker images
- Runs security scans with Trivy and Snyk
- Tests the built image
- Pushes to Docker Hub on releases

### Required Secrets
Set up these secrets in your GitHub repository:
- `DOCKERHUB_USERNAME` - Your Docker Hub username
- `DOCKERHUB_TOKEN` - Your Docker Hub access token
- `SNYK_TOKEN` - Snyk API token (optional)

## Security Features

- Runs as non-root user (`zeek`)
- Security scanning with Trivy and Snyk
- Minimal attack surface
- Regular security updates
- No unnecessary services running

## Performance Considerations

- The image is optimized for multi-stage builds
- Uses build caching for faster rebuilds
- Supports both AMD64 and ARM64 architectures
- Configurable log rotation and compression

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Run with proper capabilities
   docker run --cap-add=NET_ADMIN --cap-add=NET_RAW ...
   ```

2. **No Traffic Detected**
   ```bash
   # Check interface name
   docker run --rm nborgers/zeek:latest ip link show
   
   # Use specific interface
   docker run --rm nborgers/zeek:latest zeek -i <interface-name>
   ```

3. **Plugin Not Found**
   ```bash
   # Check available plugins
   docker run --rm nborgers/zeek:latest zeek -N
   ```

### Debug Mode
```bash
# Run with debug output
docker run --rm -it --network host nborgers/zeek:latest zeek -i eth0 -C -B comm
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the Zeek documentation
- Review the logs for error messages

## Acknowledgments

- Zeek Project for the excellent network security monitoring platform
- Docker community for containerization best practices
- All plugin developers for their contributions 