#!/bin/bash
# MITM Lab Mode: Controlled testing environment for malware analysis
# mitmproxy + Squid + CA cert injection + PCAP capture
# *** FOR AUTHORIZED TESTING ONLY ***

set -e

ROUTER_HOME="/home/mdx/mod-router"
DATADIR="/opt/mod-router"
LABDIR="/opt/mod-router/mitm-lab"
LOGDIR="/var/log/mod-router"

echo "[*] Setting up MOD-ROUTER MITM Lab Mode..."
echo "[!] WARNING: MITM decryption requires explicit device consent or policy authority"
echo "[!] Lab mode is ONLY for secure, privately-owned lab testing"

# === MITM LAB DIRECTORIES ===
mkdir -p "$LABDIR/certs" "$LABDIR/pcaps" "$LABDIR/logs" "$LABDIR/apps"
chmod 700 "$LABDIR"  # Restricted access

# === GENERATE ROOT CA FOR CERT INJECTION ===
echo "[+] Generating root CA certificate..."

openssl genrsa -out "$LABDIR/certs/mod-router-ca.key" 4096 2>/dev/null
openssl req -new -x509 -days 365 -key "$LABDIR/certs/mod-router-ca.key" \
    -out "$LABDIR/certs/mod-router-ca.pem" \
    -subj "/C=US/ST=Lab/L=TestLab/O=MOD-ROUTER/OU=MITM/CN=MOD-ROUTER Root CA" 2>/dev/null

echo "[+] CA certificate: $LABDIR/certs/mod-router-ca.pem"
echo "[+] CA key: $LABDIR/certs/mod-router-ca.key"

# === MITMPROXY CONFIGURATION ===
cat > "$LABDIR/mitmproxy-config.py" << 'EOFMITM'
"""
mitmproxy addon for MOD-ROUTER MITM lab
- Log all decrypted traffic
- Extract certificates
- Capture payloads for analysis
"""

from mitmproxy import http, ctx
from mitmproxy.net.http.http1.assemble import assemble_response_head
import json
import sqlite3
from datetime import datetime

DB_PATH = "/opt/mod-router/mod-router.db"
LOG_DIR = "/opt/mod-router/mitm-lab/logs"

class MODRouterMITM:
    def __init__(self):
        self.request_count = 0
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Log HTTP request"""
        self.request_count += 1
        
        req = flow.request
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "http_request",
            "method": req.method,
            "url": req.pretty_url,
            "host": req.host,
            "path": req.path,
            "headers": dict(req.headers),
            "content_length": len(req.content) if req.content else 0,
        }
        
        ctx.log.info(f"[MITM] {req.method} {req.pretty_url}")
        self._log_to_db(log_entry)
        
        # Save request body for suspicious traffic
        if self._is_suspicious_request(req):
            self._save_payload(f"request-{self.request_count}.bin", req.content)
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Log HTTP response"""
        resp = flow.response
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "http_response",
            "status_code": resp.status_code,
            "host": flow.request.host,
            "path": flow.request.path,
            "content_type": resp.headers.get("content-type", ""),
            "content_length": len(resp.content) if resp.content else 0,
            "headers": dict(resp.headers),
        }
        
        ctx.log.info(f"[MITM] Response: {resp.status_code} {len(resp.content or '')} bytes")
        self._log_to_db(log_entry)
        
        # Extract and store certificates
        if flow.server_conn.ssl_conn:
            cert = flow.server_conn.ssl_conn.getpeercert()
            ctx.log.info(f"[TLS] Certificate: {cert}")
    
    def tls_clienthello(self, flow):
        """Log TLS Client Hello (SNI)"""
        sni = flow.client_conn.sni
        ctx.log.info(f"[TLS-SNI] {sni}")
    
    def _is_suspicious_request(self, req: http.Request) -> bool:
        """Heuristic: identify potentially malicious traffic"""
        suspicious_patterns = [
            b"cmd.exe", b"/bin/bash", b"powershell",
            b"wget", b"curl", b"nc", b"netcat",
            b"eval", b"exec", b"system",
        ]
        
        for pattern in suspicious_patterns:
            if pattern in (req.content or b""):
                return True
        
        return False
    
    def _save_payload(self, filename: str, data: bytes) -> None:
        """Save payload for analysis"""
        try:
            with open(f"{LOG_DIR}/{filename}", "wb") as f:
                f.write(data)
        except Exception as e:
            ctx.log.error(f"Error saving payload: {e}")
    
    def _log_to_db(self, entry: dict) -> None:
        """Store MITM log in database"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO incidents (device_id, incident_type, description, severity)
                VALUES (?, ?, ?, ?)
            """, ("mitm-lab", "mitm_traffic", json.dumps(entry), "info"))
            
            conn.commit()
            conn.close()
        except Exception as e:
            ctx.log.error(f"Database error: {e}")

addons = [MODRouterMITM()]
EOFMITM

# === MITMPROXY DEPLOYMENT ===
cat > "$LABDIR/start-mitmproxy.sh" << 'EOFSH'
#!/bin/bash
# Start mitmproxy with MOD-ROUTER addons

CA_DIR="$LABDIR/certs"
CONFIG="$LABDIR/mitmproxy-config.py"
LOG_DIR="$LABDIR/logs"

echo "[*] Starting mitmproxy with MOD-ROUTER lab config..."

# Start mitmproxy
mitmproxy \
    --mode regular \
    --listen-host 0.0.0.0 \
    --listen-port 8080 \
    --set confdir="$CA_DIR" \
    --scripts "$CONFIG" \
    --flow-detail 3 \
    --logfile "$LOG_DIR/mitmproxy.log"

echo "[+] mitmproxy running on 0.0.0.0:8080"
echo "[+] Logs: $LOG_DIR/mitmproxy.log"
EOFSH

chmod +x "$LABDIR/start-mitmproxy.sh"

# === SQUID PROXY (OPTIONAL CACHING) ===
cat > "$LABDIR/squid.conf" << 'EOF'
# Squid proxy for MOD-ROUTER MITM lab
# Transparent caching + traffic analysis

http_port 3128 transparent
https_port 3129 cert=/opt/mod-router/mitm-lab/certs/mod-router-ca.pem key=/opt/mod-router/mitm-lab/certs/mod-router-ca.key

# Cache settings
cache_dir ufs /var/spool/squid 10000 16 256
cache_mem 512 MB

# Access control
acl lab_network src 192.168.0.0/16
acl lab_network src 10.0.0.0/8
http_access allow lab_network
http_access deny all

# Logging
access_log /opt/mod-router/mitm-lab/logs/squid-access.log squid
cache_log /opt/mod-router/mitm-lab/logs/squid-cache.log

# Debug
debug_options ALL,1 33,2
EOF

# === CA CERT INSTALLATION HELPER ===
cat > "$LABDIR/install-ca-on-device.sh" << 'EOFSH'
#!/bin/bash
# Helper script to install CA cert on test devices
# Requires physical or SSH access

TARGET_IP="${1:-}"
CA_CERT="/opt/mod-router/mitm-lab/certs/mod-router-ca.pem"
TARGET_CERT_PATH="${2:-/tmp/mod-router-ca.pem}"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: install-ca-on-device.sh <device_ip> [target_cert_path]"
    echo "Example: install-ca-on-device.sh 192.168.1.100"
    exit 1
fi

echo "[*] Copying CA certificate to $TARGET_IP:$TARGET_CERT_PATH"
scp "$CA_CERT" "root@$TARGET_IP:$TARGET_CERT_PATH"

echo "[*] Installing certificate..."

# Linux (Debian/Ubuntu)
ssh root@$TARGET_IP << 'EOFCERT'
cp /tmp/mod-router-ca.pem /usr/local/share/ca-certificates/mod-router-ca.crt
update-ca-certificates
echo "[+] CA certificate installed on Linux"
EOFCERT

echo "[+] Certificate installed. Device will now intercept MITM traffic."
echo "[!] WARNING: This breaks certificate pinning on most apps"
echo "[!] Accept app errors and data inconsistencies as expected"
EOFSH

chmod +x "$LABDIR/install-ca-on-device.sh"

# === TRANSPARENT PROXY SETUP ===
cat > "$LABDIR/setup-transparent-proxy.sh" << 'EOFSH'
#!/bin/bash
# Configure transparent proxy redirection for lab network

INTERFACE="${1:-eth1}"  # Lab network interface
PROXY_IP="192.168.100.1"
PROXY_PORT=8080

echo "[*] Configuring transparent proxy on $INTERFACE..."

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# iptables rules for transparent proxy
sudo iptables -t mangle -N PROXY_OUT 2>/dev/null || true
sudo iptables -t mangle -A PROXY_OUT -p tcp --dport 80 -j MARK --set-mark 1
sudo iptables -t mangle -A PROXY_OUT -p tcp --dport 443 -j MARK --set-mark 1

sudo iptables -t nat -N PROXY_REDIR 2>/dev/null || true
sudo iptables -t nat -A PROXY_REDIR -m mark --mark 1 -j REDIRECT --to-port $PROXY_PORT

# Apply rules to lab interface
sudo iptables -A FORWARD -i $INTERFACE -j ACCEPT
sudo iptables -A FORWARD -o $INTERFACE -j ACCEPT

echo "[+] Transparent proxy configured"
echo "[+] All HTTP/HTTPS from $INTERFACE routed to $PROXY_IP:$PROXY_PORT"
EOFSH

chmod +x "$LABDIR/setup-transparent-proxy.sh"

# === PCAP ANALYSIS HELPER ===
cat > "$LABDIR/analyze-pcaps.sh" << 'EOFSH'
#!/bin/bash
# Extract and analyze captured PCAPs

PCAP_DIR="/opt/mod-router/mitm-lab/pcaps"
OUTPUT_FILE="${1:-/tmp/mitm-analysis.txt}"

echo "[*] Analyzing MITM lab PCAPs..."

# Extract URLs
tshark -r "$PCAP_DIR/*.pcap" -Y 'http.request.method == "GET"' \
    -T fields -e http.host -e http.request.uri > "$OUTPUT_FILE.urls"

# Extract DNS queries
tshark -r "$PCAP_DIR/*.pcap" -Y 'dns.qry.name' \
    -T fields -e dns.qry.name > "$OUTPUT_FILE.dns"

# Extract TLS server names
tshark -r "$PCAP_DIR/*.pcap" -Y 'tls.handshake.extensions_server_name' \
    -T fields -e tls.handshake.extensions_server_name > "$OUTPUT_FILE.sni"

# Extract file transfers
tshark -r "$PCAP_DIR/*.pcap" -Y 'http.request.method == "POST"' \
    -T fields -e frame.time -e ip.src -e http.host -e http.request.uri > "$OUTPUT_FILE.posts"

echo "[+] Analysis complete:"
echo "    URLs: $OUTPUT_FILE.urls"
echo "    DNS: $OUTPUT_FILE.dns"
echo "    SNI: $OUTPUT_FILE.sni"
echo "    POSTs: $OUTPUT_FILE.posts"
EOFSH

chmod +x "$LABDIR/analyze-pcaps.sh"

# === SECURITY WARNINGS ===
cat > "$LABDIR/SECURITY_NOTICE.txt" << 'EOF'
╔════════════════════════════════════════════════════════════════════╗
║         MOD-ROUTER MITM LAB MODE - SECURITY NOTICE                ║
╚════════════════════════════════════════════════════════════════════╝

[!] This MITM lab is ONLY for testing malware and suspicious applications
    in isolated, authorized environments.

[!] LEGAL REQUIREMENTS:
    - Requires explicit written authorization from device owners
    - Cannot be used to intercept traffic on networks you don't own
    - Violates computer fraud laws if used without consent
    - Violates wiretapping/eavesdropping laws in many jurisdictions

[!] TECHNICAL WARNINGS:
    - Certificate injection breaks app security
    - Apps WILL crash due to pinning bypass
    - Session tokens may be exposed in logs
    - Private data (credentials, messages) will be visible

[!] INCIDENT RESPONSE:
    1. All MITM sessions logged to: /opt/mod-router/mitm-lab/logs
    2. Keep detailed notes of test objectives
    3. Delete lab data immediately after testing
    4. Never export MITM logs outside lab environment

[!] COMPLIANCE:
    - GDPR: May violate if personal data is intercepted
    - HIPAA: Prohibited in healthcare environments
    - PCI-DSS: Incompatible with payment card testing
    - SOC2: Auditors will flag unauthorized MITM activity

[!] IF IN DOUBT, DO NOT PROCEED
EOF

cat "$LABDIR/SECURITY_NOTICE.txt"

echo ""
echo "[+] MITM Lab Mode initialized!"
echo "[+] Components:"
echo "    - mitmproxy config: $LABDIR/mitmproxy-config.py"
echo "    - Root CA: $LABDIR/certs/mod-router-ca.pem"
echo "    - Squid config: $LABDIR/squid.conf"
echo ""
echo "[*] To use MITM lab:"
echo "    1. Review SECURITY_NOTICE.txt"
echo "    2. Install CA cert on test device: $LABDIR/install-ca-on-device.sh 192.168.x.x"
echo "    3. Configure transparent proxy: $LABDIR/setup-transparent-proxy.sh eth1"
echo "    4. Start mitmproxy: $LABDIR/start-mitmproxy.sh"
echo "    5. Test device traffic will be intercepted + logged"
