#!/bin/bash
# MOD-ROUTER: Main deployment script
# Deploys: Pi-hole + Unbound + Zeek + Arkime + forensic pipeline

set -e

ROUTER_HOME="/home/mdx/mod-router"
LOGDIR="/var/log/mod-router"
DATADIR="/opt/mod-router"
PCAP_DIR="/var/lib/mod-router/pcaps"
FLOWS_DIR="/var/lib/mod-router/flows"

echo "[*] MOD-ROUTER Forensic Stack Deployment"
echo "[*] Home: $ROUTER_HOME"

# === SYSTEM PREP ===
echo "[+] System prerequisites..."
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config \
  libpcap-dev libssl-dev zlib1g-dev \
  python3-pip python3-venv \
  git curl wget \
  net-tools tcpdump tshark \
  sqlite3 jq \
  dnsmasq dnsutils \
  zeek suricata \
  geoip-database geoip-database-extra

# === DIRECTORIES ===
echo "[+] Creating directories..."
sudo mkdir -p "$LOGDIR" "$DATADIR" "$PCAP_DIR" "$FLOWS_DIR"
sudo chmod 755 "$LOGDIR" "$DATADIR" "$PCAP_DIR" "$FLOWS_DIR"
sudo chown "$USER:$USER" "$LOGDIR" "$DATADIR" "$PCAP_DIR" "$FLOWS_DIR"

# === PYTHON ENVIRONMENT ===
echo "[+] Setting up Python environment..."
python3 -m venv "$ROUTER_HOME/.venv"
source "$ROUTER_HOME/.venv/bin/activate"
pip install --upgrade pip setuptools wheel
pip install \
  requests \
  geoip2 \
  dpkt \
  scapy \
  pyyaml \
  sqlite3 \
  arrow \
  pandas

# === DATABASE SCHEMAS ===
echo "[+] Initializing forensic databases..."
sqlite3 "$DATADIR/mod-router.db" << 'EOF'
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
EOF

echo "[+] Database initialized: $DATADIR/mod-router.db"

# === ZEEK CONFIGURATION ===
echo "[+] Configuring Zeek..."
mkdir -p "$ROUTER_HOME/zeek/policies"

# === FINISH ===
echo "[+] MOD-ROUTER deployment initialized!"
echo "[+] Next steps:"
echo "    1. ./scripts/01-zeek-config.sh"
echo "    2. ./scripts/02-dns-authority.sh"
echo "    3. ./scripts/03-device-timeline.sh"
