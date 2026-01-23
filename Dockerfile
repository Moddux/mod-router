# MOD-ROUTER: Forensic DNS + Network Audit Stack
# Production-grade Dockerfile for network forensics platform
# Supports: DNS authority, Zeek network forensics, device tracking, incident response

FROM debian:bookworm-slim AS builder

# Metadata
LABEL maintainer="MOD-ROUTER Contributors"
LABEL description="Production forensic DNS + network audit stack"
LABEL version="1.0.0"

# Build arguments
ARG DEBIAN_FRONTEND=noninteractive
ARG APT_OPTS="-qq -y --no-install-recommends"

# Install build dependencies
RUN apt-get update && apt-get install ${APT_OPTS} \
    build-essential pkg-config git \
    libpcap-dev libssl-dev zlib1g-dev \
    cmake

# Build Python extensions (optional, for faster installation)
# (Most packages come pre-built from PyPI)

RUN echo "Builder stage complete"

# ============================================================================
# RUNTIME STAGE
# ============================================================================

FROM debian:bookworm-slim

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/mod-router/.venv/bin:${PATH}"
ENV MOD_ROUTER_HOME="/opt/mod-router"
ENV MOD_ROUTER_DB="/opt/mod-router/mod-router.db"
ENV MOD_ROUTER_LOGS="/var/log/mod-router"
ENV MOD_ROUTER_PCAPS="/var/lib/mod-router/pcaps"

# Create non-root user for security
RUN groupadd -r mod-router && useradd -r -g mod-router -d /opt/mod-router mod-router

# Install system dependencies (minimal + production essentials)
RUN apt-get update && apt-get install ${APT_OPTS} \
    # DNS services
    dnsmasq dnsutils bind9-utils \
    unbound knot-resolver \
    # Network forensics
    zeek suricata \
    net-tools tcpdump tshark \
    # Python runtime
    python3 python3-venv python3-dev \
    python3-pip \
    # Development tools (minimal)
    git curl wget ca-certificates \
    # Database
    sqlite3 \
    # JSON processing
    jq yq \
    # Optional: mitmproxy
    mitmproxy \
    # Utilities
    iputils-ping procps less \
    # System tools
    sudo systemctl openssh-client \
    # GeoIP databases
    geoip-database geoip-database-extra \
    # Cleanup
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create directory structure
RUN mkdir -p \
    /opt/mod-router \
    /var/log/mod-router \
    /var/lib/mod-router/pcaps \
    /var/lib/mod-router/flows \
    /var/spool/mod-router \
    /opt/mod-router/zeek/policies \
    /opt/mod-router/mitm-lab/certs \
    && chown -R mod-router:mod-router \
    /opt/mod-router \
    /var/log/mod-router \
    /var/lib/mod-router \
    /var/spool/mod-router

# Setup Python virtual environment
RUN python3 -m venv /opt/mod-router/.venv && \
    /opt/mod-router/.venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/mod-router/.venv/bin/pip install --no-cache-dir \
    # Core dependencies (pinned versions)
    requests==2.31.0 \
    geoip2==4.7.0 \
    dpkt==1.9.7 \
    scapy==2.5.0 \
    pyyaml==6.0.1 \
    arrow==1.3.0 \
    pandas==2.1.4 \
    mitmproxy==10.1.1

# Copy MOD-ROUTER code and scripts (from git or local)
# Note: In production, use COPY from local build context
COPY scripts/ /opt/mod-router/scripts/
COPY zeek/ /opt/mod-router/zeek/ 2>/dev/null || true

# Extract and embed Python utilities from scripts
# (These are embedded in bash scripts; we'll extract them)
RUN mkdir -p /opt/mod-router/utils && \
    chmod +x /opt/mod-router/scripts/*.sh

# Create Python utility extraction script
RUN cat > /opt/mod-router/extract-python-utils.sh << 'EXTRACT_EOF'
#!/bin/bash
# Extract Python scripts from bash deployment scripts

extract_python_script() {
    local bash_file=$1
    local script_name=$2
    local python_file="/opt/mod-router/utils/${script_name}.py"
    
    # Extract Python code between EOFPYTHON markers
    sed -n '/^cat > .*\.py.*<< '"'"'EOFPYTHON'"'"'$/,/^EOFPYTHON$/p' "$bash_file" | \
        sed '1d;$d' > "$python_file" 2>/dev/null || true
    
    [ -f "$python_file" ] && chmod +x "$python_file"
}

# Extract all Python utilities
extract_python_script "/opt/mod-router/scripts/03-device-timeline.sh" "device-timeline-builder"
extract_python_script "/opt/mod-router/scripts/03-device-timeline.sh" "asn-enrichment"
extract_python_script "/opt/mod-router/scripts/03-device-timeline.sh" "incident-report"
extract_python_script "/opt/mod-router/scripts/04-doh-detection.sh" "doh-analyzer"

# Symlink to standard locations
ln -sf /opt/mod-router/utils/device-timeline-builder.py /opt/mod-router/device-timeline-builder.py
ln -sf /opt/mod-router/utils/asn-enrichment.py /opt/mod-router/asn-enrichment.py
ln -sf /opt/mod-router/utils/incident-report.py /opt/mod-router/incident-report.py
ln -sf /opt/mod-router/utils/doh-analyzer.py /opt/mod-router/doh-analyzer.py

echo "[+] Python utilities extracted"
EXTRACT_EOF

chmod +x /opt/mod-router/extract-python-utils.sh && \
    /opt/mod-router/extract-python-utils.sh

# Create entrypoint script
RUN cat > /opt/mod-router/entrypoint.sh << 'ENTRYPOINT_EOF'
#!/bin/bash
set -e

# MOD-ROUTER Container Entrypoint
# Initializes and starts forensic DNS/network audit stack

MOD_ROUTER_HOME="/opt/mod-router"
MOD_ROUTER_DB="/opt/mod-router/mod-router.db"
MOD_ROUTER_LOGS="/var/log/mod-router"

# Initialize database if needed
if [ ! -f "$MOD_ROUTER_DB" ]; then
    echo "[*] Initializing forensic database..."
    sqlite3 "$MOD_ROUTER_DB" << 'SQL_INIT'
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    mac_addr TEXT UNIQUE,
    ipv4_addr TEXT,
    hostname TEXT,
    dhcp_lease_start DATETIME,
    dhcp_lease_end DATETIME,
    user_agent TEXT,
    device_type TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_queries (
    query_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    device_id TEXT,
    client_ip TEXT,
    client_mac TEXT,
    queried_domain TEXT,
    query_type TEXT,
    response_ips TEXT,
    ttl INTEGER,
    is_blocked INTEGER DEFAULT 0,
    resolver_used TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(device_id),
    INDEX idx_domain(queried_domain),
    INDEX idx_device(device_id),
    INDEX idx_timestamp(timestamp)
);

CREATE TABLE IF NOT EXISTS flows (
    flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    device_id TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    bytes_in INTEGER,
    bytes_out INTEGER,
    duration REAL,
    ja3 TEXT,
    sni TEXT,
    is_quic INTEGER DEFAULT 0,
    is_doh INTEGER DEFAULT 0,
    asn TEXT,
    geo_country TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(device_id),
    INDEX idx_device(device_id),
    INDEX idx_timestamp(timestamp),
    INDEX idx_dst_ip(dst_ip)
);

CREATE TABLE IF NOT EXISTS asn_cache (
    ip_addr TEXT PRIMARY KEY,
    asn INTEGER,
    asn_name TEXT,
    country_code TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS doh_indicators (
    blocked_ip TEXT PRIMARY KEY,
    provider TEXT,
    description TEXT,
    dateadded DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    device_id TEXT,
    incident_type TEXT,
    description TEXT,
    severity TEXT,
    related_flows TEXT,
    resolved INTEGER DEFAULT 0,
    FOREIGN KEY(device_id) REFERENCES devices(device_id)
);

CREATE VIEW IF NOT EXISTS device_timeline AS
SELECT 
    d.device_id,
    d.mac_addr,
    d.ipv4_addr,
    d.hostname,
    dns.timestamp as event_timestamp,
    'DNS' as event_type,
    dns.queried_domain as event_data,
    asn.asn_name as owner
FROM devices d
LEFT JOIN dns_queries dns ON d.device_id = dns.device_id
LEFT JOIN asn_cache asn ON dns.response_ips = asn.ip_addr
ORDER BY d.device_id, dns.timestamp DESC;
SQL_INIT
    echo "[+] Database initialized: $MOD_ROUTER_DB"
    chmod 644 "$MOD_ROUTER_DB"
fi

# Ensure log directories exist
mkdir -p "$MOD_ROUTER_LOGS"/{zeek,timelines}
chmod 755 "$MOD_ROUTER_LOGS"

echo "[*] MOD-ROUTER container ready"
echo "[*] Services available:"
echo "    - dnsmasq (port 53)"
echo "    - Unbound (port 5353)"
echo "    - Knot Resolver (port 5354)"
echo "[*] Database: $MOD_ROUTER_DB"
echo "[*] Logs: $MOD_ROUTER_LOGS"
echo "[*] To start services, run:"
echo "    docker exec <container> bash /opt/mod-router/scripts/00-deploy-stack.sh"

# Keep container running
exec "$@"
ENTRYPOINT_EOF

chmod +x /opt/mod-router/entrypoint.sh

# Create health check script
RUN cat > /opt/mod-router/healthcheck.sh << 'HEALTHCHECK_EOF'
#!/bin/bash
# Health check: verify DNS services are responding

# Check dnsmasq
timeout 2 dig @127.0.0.1 -p 53 example.com +short > /dev/null 2>&1 || exit 1

# Check Unbound
timeout 2 dig @127.0.0.1 -p 5353 example.com +short > /dev/null 2>&1 || exit 1

# Check database
sqlite3 /opt/mod-router/mod-router.db "SELECT COUNT(*) FROM devices;" > /dev/null 2>&1 || exit 1

exit 0
HEALTHCHECK_EOF

chmod +x /opt/mod-router/healthcheck.sh

# Create DNS configuration templates
RUN cat > /opt/mod-router/config/unbound.conf << 'UNBOUND_CONF'
server:
    interface: 0.0.0.0
    interface: ::0
    port: 5353
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    
    auto-trust-anchor: yes
    log-queries: yes
    log-replies: yes
    logfile: "/var/log/mod-router/unbound-queries.log"
    log-time-ascii: yes
    
    num-threads: 4
    outgoing-port-avoid: "0-32767"
    cache-max-ttl: 86400
    cache-min-ttl: 300

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
UNBOUND_CONF

RUN mkdir -p /opt/mod-router/config && cat > /opt/mod-router/config/dnsmasq.conf << 'DNSMASQ_CONF'
interface=*
bind-interfaces
port=53

server=127.0.0.1#5353
server=1.1.1.1#53
server=8.8.8.8#53

dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
dhcp-leasefile=/var/lib/dnsmasq/dhcp.leases

log-queries=extra
log-facility=/var/log/mod-router/dnsmasq-queries.log

cache-size=10000
neg-ttl=3600

conf-dir=/etc/dnsmasq.d/,*.conf
DNSMASQ_CONF

# Set permissions
RUN chown -R mod-router:mod-router /opt/mod-router && \
    chmod -R 755 /opt/mod-router

# Set working directory
WORKDIR /opt/mod-router

# Switch to non-root user
USER mod-router

# Expose ports
EXPOSE 53/udp 53/tcp      # dnsmasq DNS
EXPOSE 5353/udp 5353/tcp  # Unbound resolver
EXPOSE 5354/udp 5354/tcp  # Knot Resolver
EXPOSE 8080/tcp           # mitmproxy (optional)

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD /opt/mod-router/healthcheck.sh || exit 1

# Default entrypoint
ENTRYPOINT ["/opt/mod-router/entrypoint.sh"]
CMD ["sleep", "infinity"]

# Metadata
LABEL org.opencontainers.image.title="MOD-ROUTER"
LABEL org.opencontainers.image.description="Forensic DNS + Network Audit Stack"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/Moddux/mod-router"

# ============================================================================
# Usage:
# ============================================================================
# 
# Build:
#   docker build -t mod-router:latest .
#
# Run with Docker Compose:
#   docker-compose up -d
#
# Run standalone:
#   docker run -d \
#     --name mod-router \
#     --cap-add NET_RAW \
#     --cap-add NET_ADMIN \
#     --cap-add NET_BIND_SERVICE \
#     -p 53:53/udp \
#     -p 5353:5353/tcp \
#     -v mod-router-db:/opt/mod-router \
#     -v mod-router-logs:/var/log/mod-router \
#     mod-router:latest
#
# Initialize services:
#   docker exec mod-router bash /opt/mod-router/scripts/00-deploy-stack.sh
#
# Start Zeek (requires host network access):
#   docker run --net host \
#     --cap-add NET_RAW \
#     -v /var/log/zeek:/var/log/mod-router/zeek \
#     mod-router:latest \
#     zeek -i eth0 /opt/mod-router/zeek/policies/mod-router.zeek
#
# ============================================================================
