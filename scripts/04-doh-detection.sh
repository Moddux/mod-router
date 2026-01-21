#!/bin/bash
# DoH/VPN Detection and Blocking Framework
# Detect encrypted DNS, block known DoH endpoints, flag suspicious patterns

set -e

DATADIR="/opt/mod-router"
LOGDIR="/var/log/mod-router"

echo "[*] Deploying DoH detection and blocking system..."

# === DOH ENDPOINT BLOCKLIST ===
cat > "$DATADIR/doh-blocklist.txt" << 'EOF'
# Known DoH endpoint IPs and domains (update monthly)
# Format: ip_or_domain|provider

1.1.1.1|Cloudflare
1.0.0.1|Cloudflare
8.8.8.8|Google
8.8.4.4|Google
208.67.222.222|OpenDNS
208.67.220.220|OpenDNS
9.9.9.9|Quad9
149.112.112.112|Quad9
dns.google|Google
dns.quad9.net|Quad9
dns.cloudflare.com|Cloudflare
dns.apple.com|Apple
2001:4860:4860::8888|Google-IPv6
2606:4700:4700::1111|Cloudflare-IPv6
EOF

# === DOH DETECTION ZEEK POLICY ===
cat > "$DATADIR/zeek-doh-policy.zeek" << 'EOF'
# Zeek policy for DoH detection and alerting

@load base/protocols/http
@load base/protocols/dns
@load base/protocols/quic

module DOH_DETECT;

export {
    global doh_providers: set[string] = {
        "dns.google", "dns.cloudflare.com", "dns.apple.com",
        "dns.quad9.net", "doh.opendns.com"
    } &redef;
    
    global doh_ports: set[port] = { 443/tcp, 8443/tcp } &redef;
}

# Detect DoH via HTTP/3 (QUIC)
event quic_client_initial(c: connection, version: count, supported_versions: vector of count) {
    for ( provider in doh_providers ) {
        if ( c$id$resp_h in doh_providers || 
             (c?$ssl && c$ssl?$server_name && provider in c$ssl$server_name) ) {
            NOTICE([$note=Notice::DoH_Detected,
                    $conn=c,
                    $msg=fmt("DoH detected via QUIC: %s", provider)]);
            print fmt("[DoH_QUIC] %s -> %s (provider=%s)", c$id$orig_h, c$id$resp_h, provider);
        }
    }
}

# Detect DoH via HTTP POST to /dns-query or /dns-pad
event http_request(c: connection, method: string, uri: string, version: string, headers: http_header_table) {
    if ( method == "POST" && (/dns-query/ in uri || /dns-pad/ in uri) ) {
        NOTICE([$note=Notice::DoH_Detected,
                $conn=c,
                $msg=fmt("DoH detected via HTTP/POST: %s %s", method, uri)]);
        print fmt("[DoH_HTTP] %s -> %s (uri=%s)", c$id$orig_h, c$id$resp_h, uri);
        
        # Log to database
        local db_cmd = fmt("sqlite3 /opt/mod-router/mod-router.db \"INSERT INTO incidents (device_id, incident_type, description, severity) SELECT device_id, 'DoH_Detected', '%s %s', 'medium' FROM devices WHERE ipv4_addr = '%s'\"", method, uri, c$id$orig_h);
    }
}

# Detect DNS over TLS (port 853)
event connection_established(c: connection) {
    if ( c$id$resp_p == 853/tcp ) {
        NOTICE([$note=Notice::DoH_Detected,
                $conn=c,
                $msg=fmt("DNS-over-TLS detected: %s -> %s:853", c$id$orig_h, c$id$resp_h)]);
        print fmt("[DoT_TLS] %s -> %s:853 (DNS-over-TLS)", c$id$orig_h, c$id$resp_h);
    }
}
EOF

# === NFTABLES/iptables RULES FOR BLOCKING ===
cat > "$DATADIR/block-doh.sh" << 'EOFSH'
#!/bin/bash
# Deploy nftables rules to block DoH endpoints

echo "[*] Deploying DoH blocking rules..."

# Create nftables table
sudo nft add table inet doh_block 2>/dev/null || true
sudo nft add chain inet doh_block doh_out { type filter hook output priority 0 \; }
sudo nft add chain inet doh_block doh_forward { type filter hook forward priority 0 \; }

# Block known DoH IPs
declare -a DOH_IPS=(
    "1.1.1.1" "1.0.0.1"           # Cloudflare
    "8.8.8.8" "8.8.4.4"           # Google
    "9.9.9.9" "149.112.112.112"   # Quad9
    "208.67.222.222" "208.67.220.220"  # OpenDNS
)

for ip in "${DOH_IPS[@]}"; do
    sudo nft add rule inet doh_block doh_out ip daddr "$ip" tcp dport 443 drop 2>/dev/null || true
    sudo nft add rule inet doh_block doh_forward ip daddr "$ip" tcp dport 443 drop 2>/dev/null || true
    echo "  [+] Blocking $ip:443"
done

# Block DNS-over-TLS (port 853)
sudo nft add rule inet doh_block doh_out tcp dport 853 drop 2>/dev/null || true
sudo nft add rule inet doh_block doh_forward tcp dport 853 drop 2>/dev/null || true

# Block QUIC on port 443 (encrypted DNS)
sudo nft add rule inet doh_block doh_out udp dport 443 drop 2>/dev/null || true
sudo nft add rule inet doh_block doh_forward udp dport 443 drop 2>/dev/null || true

echo "[+] DoH blocking rules applied"
EOFSH

chmod +x "$DATADIR/block-doh.sh"

# === DOH DETECTION ANALYZER ===
cat > "$DATADIR/doh-analyzer.py" << 'EOFPYTHON'
#!/usr/bin/env python3
"""
DoH/VPN Detection Analyzer
Analyzes flows and DNS patterns for encrypted DNS usage
"""

import sqlite3
import sys
from collections import defaultdict
import json

DB_PATH = "/opt/mod-router/mod-router.db"

class DoHAnalyzer:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        
        # Known DoH providers (ASNs and IPs)
        self.doh_providers = {
            "1.1.1.1": "Cloudflare",
            "1.0.0.1": "Cloudflare",
            "8.8.8.8": "Google",
            "8.8.4.4": "Google",
            "9.9.9.9": "Quad9",
            "208.67.222.222": "OpenDNS",
            "dns.google": "Google",
            "dns.cloudflare.com": "Cloudflare",
        }
        
        self.quic_asns = ["AS15169", "AS13335", "AS8452"]  # Google, Cloudflare, etc
    
    def detect_doh_indicators(self, device_id):
        """Detect indicators of DoH usage"""
        indicators = []
        
        # 1. Connections to known DoH IPs on port 443
        self.cursor.execute("""
            SELECT COUNT(*) as count, dst_ip
            FROM flows
            WHERE device_id = ? AND dst_port = 443 AND protocol = 'tcp'
            GROUP BY dst_ip
            ORDER BY count DESC
        """, (device_id,))
        
        for row in self.cursor.fetchall():
            ip = row[1]
            if ip in self.doh_providers:
                indicators.append({
                    "type": "direct_doh_ip",
                    "provider": self.doh_providers[ip],
                    "ip": ip,
                    "flow_count": row[0],
                    "severity": "high"
                })
        
        # 2. QUIC/UDP 443 usage (DNS-over-QUIC)
        self.cursor.execute("""
            SELECT COUNT(*) as count FROM flows
            WHERE device_id = ? AND dst_port = 443 AND (protocol = 'quic' OR protocol = 'udp')
        """, (device_id,))
        
        quic_count = self.cursor.fetchone()[0]
        if quic_count > 0:
            indicators.append({
                "type": "dns_over_quic",
                "flow_count": quic_count,
                "severity": "high",
                "description": "Detected QUIC/UDP to port 443 (potential DoH)"
            })
        
        # 3. DNS queries > 0 BUT no port 53 traffic (indicates encrypted DNS)
        self.cursor.execute("""
            SELECT COUNT(*) from dns_queries WHERE device_id = ?
        """, (device_id,))
        dns_query_count = self.cursor.fetchone()[0]
        
        self.cursor.execute("""
            SELECT COUNT(*) from flows 
            WHERE device_id = ? AND dst_port = 53
        """, (device_id,))
        port_53_count = self.cursor.fetchone()[0]
        
        if dns_query_count > 100 and port_53_count == 0:
            indicators.append({
                "type": "no_clear_dns_traffic",
                "dns_queries": dns_query_count,
                "port_53_flows": port_53_count,
                "severity": "high",
                "description": "Device using DNS without clear-text queries (encrypted DNS likely)"
            })
        
        # 4. TLS connections with no hostname (encrypted SNI)
        self.cursor.execute("""
            SELECT COUNT(*) as count FROM flows
            WHERE device_id = ? AND sni IS NULL AND protocol IN ('tls', 'tcp')
            AND dst_port = 443
        """, (device_id,))
        
        esni_count = self.cursor.fetchone()[0]
        if esni_count > 50:
            indicators.append({
                "type": "encrypted_sni",
                "flow_count": esni_count,
                "severity": "medium",
                "description": "Connections with encrypted/missing SNI (ESNI/ECH usage)"
            })
        
        return indicators
    
    def detect_vpn_usage(self, device_id):
        """Detect VPN usage from flow patterns"""
        vpn_indicators = []
        
        # Check for multiple ASNs from single device (VPN hopping)
        self.cursor.execute("""
            SELECT asn, COUNT(*) as count FROM flows
            WHERE device_id = ?
            GROUP BY asn
            ORDER BY count DESC
        """, (device_id,))
        
        asns = self.cursor.fetchall()
        if len(asns) > 10:
            vpn_indicators.append({
                "type": "vpn_suspected",
                "unique_asns": len(asns),
                "severity": "high",
                "description": f"Device routed through {len(asns)} different ASNs"
            })
        
        # Check for known VPN provider ASNs
        for row in asns:
            asn = row[0]
            if asn in ["AS16276", "AS6939", "AS201814"]:  # Popular VPN ASNs
                vpn_indicators.append({
                    "type": "known_vpn_asn",
                    "asn": asn,
                    "severity": "high"
                })
        
        return vpn_indicators
    
    def generate_report(self, device_id):
        """Generate comprehensive DoH/VPN detection report"""
        doh_indicators = self.detect_doh_indicators(device_id)
        vpn_indicators = self.detect_vpn_usage(device_id)
        
        report = {
            "device_id": device_id,
            "doh_indicators": doh_indicators,
            "vpn_indicators": vpn_indicators,
            "is_doh_user": len([i for i in doh_indicators if i["severity"] == "high"]) > 0,
            "is_vpn_user": len([i for i in vpn_indicators if i["severity"] == "high"]) > 0
        }
        
        return report

def main():
    analyzer = DoHAnalyzer()
    
    if len(sys.argv) > 1:
        device_id = sys.argv[1]
        report = analyzer.generate_report(device_id)
        print(json.dumps(report, indent=2))
    else:
        # Scan all devices
        analyzer.cursor.execute("SELECT device_id FROM devices")
        devices = [row[0] for row in analyzer.cursor.fetchall()]
        
        reports = {}
        for device_id in devices:
            reports[device_id] = analyzer.generate_report(device_id)
        
        print(json.dumps(reports, indent=2, default=str))
    
    analyzer.conn.close()

if __name__ == "__main__":
    main()
EOFPYTHON

chmod +x "$DATADIR/doh-analyzer.py"

echo "[+] DoH detection system deployed!"
echo "[+] Tools:"
echo "    - Zeek policy: $DATADIR/zeek-doh-policy.zeek"
echo "    - nftables rules: ./block-doh.sh"
echo "    - DoH analyzer: python3 $DATADIR/doh-analyzer.py <device_id>"
