# Multi-stage build for Zeek with comprehensive plugins
FROM ubuntu:22.04 as builder

# Set environment variables
ENV ZEEK_VERSION=6.0.0
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    libssl-dev \
    python3 \
    python3-dev \
    python3-pip \
    swig \
    bison \
    flex \
    libmaxminddb-dev \
    libcurl4-openssl-dev \
    libgeoip-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    libpcre3-dev \
    libsnappy-dev \
    libzstd-dev \
    libbz2-dev \
    liblz4-dev \
    libjemalloc-dev \
    libunwind-dev \
    libgoogle-perftools-dev \
    libgtest-dev \
    libbenchmark-dev \
    && rm -rf /var/lib/apt/lists/*

# Create zeek user
RUN useradd -m -s /bin/bash zeek

# Download and build Zeek
WORKDIR /tmp
RUN wget https://github.com/zeek/zeek/releases/download/v${ZEEK_VERSION}/zeek-${ZEEK_VERSION}.tar.gz \
    && tar -xzf zeek-${ZEEK_VERSION}.tar.gz \
    && cd zeek-${ZEEK_VERSION} \
    && ./configure --prefix=/opt/zeek \
    && make -j$(nproc) \
    && make install

# Install Zeek plugins
WORKDIR /tmp/plugins

# ARP Plugin
RUN git clone https://github.com/zeek/zeek-plugin-arp.git \
    && cd zeek-plugin-arp \
    && /opt/zeek/bin/zeek -N zeek-plugin-arp \
    && /opt/zeek/bin/zeek -N zeek-plugin-arp -b . \
    && cd ..

# DHCP Plugin
RUN git clone https://github.com/zeek/zeek-plugin-dhcp.git \
    && cd zeek-plugin-dhcp \
    && /opt/zeek/bin/zeek -N zeek-plugin-dhcp \
    && /opt/zeek/bin/zeek -N zeek-plugin-dhcp -b . \
    && cd ..

# mDNS Plugin
RUN git clone https://github.com/zeek/zeek-plugin-mdns.git \
    && cd zeek-plugin-mdns \
    && /opt/zeek/bin/zeek -N zeek-plugin-mdns \
    && /opt/zeek/bin/zeek -N zeek-plugin-mdns -b . \
    && cd ..

# NetBIOS Plugin
RUN git clone https://github.com/zeek/zeek-plugin-netbios.git \
    && cd zeek-plugin-netbios \
    && /opt/zeek/bin/zeek -N zeek-plugin-netbios \
    && /opt/zeek/bin/zeek -N zeek-plugin-netbios -b . \
    && cd ..

# LLMNR Plugin
RUN git clone https://github.com/zeek/zeek-plugin-llmnr.git \
    && cd zeek-plugin-llmnr \
    && /opt/zeek/bin/zeek -N zeek-plugin-llmnr \
    && /opt/zeek/bin/zeek -N zeek-plugin-llmnr -b . \
    && cd ..

# NTP Plugin
RUN git clone https://github.com/zeek/zeek-plugin-ntp.git \
    && cd zeek-plugin-ntp \
    && /opt/zeek/bin/zeek -N zeek-plugin-ntp \
    && /opt/zeek/bin/zeek -N zeek-plugin-ntp -b . \
    && cd ..

# SNMP Plugin
RUN git clone https://github.com/zeek/zeek-plugin-snmp.git \
    && cd zeek-plugin-snmp \
    && /opt/zeek/bin/zeek -N zeek-plugin-snmp \
    && /opt/zeek/bin/zeek -N zeek-plugin-snmp -b . \
    && cd ..

# TFTP Plugin
RUN git clone https://github.com/zeek/zeek-plugin-tftp.git \
    && cd zeek-plugin-tftp \
    && /opt/zeek/bin/zeek -N zeek-plugin-tftp \
    && /opt/zeek/bin/zeek -N zeek-plugin-tftp -b . \
    && cd ..

# Syslog Plugin
RUN git clone https://github.com/zeek/zeek-plugin-syslog.git \
    && cd zeek-plugin-syslog \
    && /opt/zeek/bin/zeek -N zeek-plugin-syslog \
    && /opt/zeek/bin/zeek -N zeek-plugin-syslog -b . \
    && cd ..

# Modbus Plugin
RUN git clone https://github.com/zeek/zeek-plugin-modbus.git \
    && cd zeek-plugin-modbus \
    && /opt/zeek/bin/zeek -N zeek-plugin-modbus \
    && /opt/zeek/bin/zeek -N zeek-plugin-modbus -b . \
    && cd ..

# DNP3 Plugin
RUN git clone https://github.com/zeek/zeek-plugin-dnp3.git \
    && cd zeek-plugin-dnp3 \
    && /opt/zeek/bin/zeek -N zeek-plugin-dnp3 \
    && /opt/zeek/bin/zeek -N zeek-plugin-dnp3 -b . \
    && cd ..

# BACnet Plugin
RUN git clone https://github.com/zeek/zeek-plugin-bacnet.git \
    && cd zeek-plugin-bacnet \
    && /opt/zeek/bin/zeek -N zeek-plugin-bacnet \
    && /opt/zeek/bin/zeek -N zeek-plugin-bacnet -b . \
    && cd ..

# SMB Plugin
RUN git clone https://github.com/zeek/zeek-plugin-smb.git \
    && cd zeek-plugin-smb \
    && /opt/zeek/bin/zeek -N zeek-plugin-smb \
    && /opt/zeek/bin/zeek -N zeek-plugin-smb -b . \
    && cd ..

# RDP Plugin
RUN git clone https://github.com/zeek/zeek-plugin-rdp.git \
    && cd zeek-plugin-rdp \
    && /opt/zeek/bin/zeek -N zeek-plugin-rdp \
    && /opt/zeek/bin/zeek -N zeek-plugin-rdp -b . \
    && cd ..

# Final stage
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/zeek/bin:${PATH}"
ENV ZEEKPATH="/opt/zeek/share/zeek:/opt/zeek/share/zeek/policy:/opt/zeek/share/zeek/site"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libssl3 \
    python3 \
    python3-pip \
    libmaxminddb0 \
    libcurl4 \
    libgeoip1 \
    libnetfilter-queue1 \
    libnfnetlink0 \
    libpcre3 \
    libsnappy1v5 \
    libzstd1 \
    libbz2-1.0 \
    liblz4-1 \
    libjemalloc2 \
    libunwind8 \
    libgoogle-perftools4 \
    ca-certificates \
    wget \
    curl \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create zeek user
RUN useradd -m -s /bin/bash zeek

# Copy Zeek installation from builder
COPY --from=builder /opt/zeek /opt/zeek

# Copy plugin installations
COPY --from=builder /tmp/plugins/*/build /opt/zeek/lib/zeek/plugins/

# Create necessary directories
RUN mkdir -p /opt/zeek/logs /opt/zeek/spool /opt/zeek/etc \
    && chown -R zeek:zeek /opt/zeek

# Copy default configuration
COPY zeek-config.zeek /opt/zeek/etc/zeek-config.zeek
COPY local.zeek /opt/zeek/share/zeek/site/local.zeek

# Set up entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to zeek user
USER zeek

# Expose ports for various protocols
EXPOSE 53/udp 67/udp 68/udp 123/udp 161/udp 162/udp 5353/udp 137/udp 138/udp 139/tcp 445/tcp

# Set working directory
WORKDIR /opt/zeek

# Default command
ENTRYPOINT ["/entrypoint.sh"]
CMD ["zeek", "-i", "eth0", "-C"] 