#!/bin/bash
# Device behavioral timeline builder
# Correlates: DHCP leases, DNS queries, flows, ASN ownership
# Produces: per-device incident timelines, forensic artifacts

set -e

ROUTER_HOME="/home/mdx/mod-router"
DATADIR="/opt/mod-router"
LOGDIR="/var/log/mod-router"

echo "[*] Building device behavioral timeline system..."

# === DEVICE TIMELINE BUILDER ===
cat > "$DATADIR/device-timeline-builder.py" << 'EOFPYTHON'
#!/usr/bin/env python3
"""
MOD-ROUTER Device Timeline Builder
Correlates DNS queries, flow logs, and ASN data into behavioral profiles
"""

import sqlite3
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

DB_PATH = "/opt/mod-router/mod-router.db"

class DeviceTimeline:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
    
    def get_device_timeline(self, device_id, hours=24):
        """Generate timeline for single device (last N hours)"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        self.cursor.execute("""
            SELECT 
                d.device_id,
                d.mac_addr,
                d.ipv4_addr,
                d.hostname,
                d.device_type,
                COUNT(DISTINCT dns.queried_domain) as unique_domains,
                COUNT(DISTINCT f.dst_ip) as unique_destinations,
                SUM(f.bytes_in + f.bytes_out) as total_bytes,
                MIN(COALESCE(dns.timestamp, f.timestamp)) as first_activity,
                MAX(COALESCE(dns.timestamp, f.timestamp)) as last_activity
            FROM devices d
            LEFT JOIN dns_queries dns ON d.device_id = dns.device_id AND dns.timestamp > ?
            LEFT JOIN flows f ON d.device_id = f.device_id AND f.timestamp > ?
            WHERE d.device_id = ?
            GROUP BY d.device_id
        """, (cutoff, cutoff, device_id))
        
        device = self.cursor.fetchone()
        if not device:
            return None
        
        # Get DNS queries
        self.cursor.execute("""
            SELECT timestamp, queried_domain, response_ips, is_blocked
            FROM dns_queries
            WHERE device_id = ? AND timestamp > ?
            ORDER BY timestamp DESC
        """, (device_id, cutoff))
        
        dns_events = [dict(row) for row in self.cursor.fetchall()]
        
        # Get flows
        self.cursor.execute("""
            SELECT timestamp, dst_ip, dst_port, protocol, bytes_in, bytes_out, 
                   ja3, sni, is_doh, asn, geo_country
            FROM flows
            WHERE device_id = ? AND timestamp > ?
            ORDER BY timestamp DESC
        """, (device_id, cutoff))
        
        flow_events = [dict(row) for row in self.cursor.fetchall()]
        
        return {
            "device": dict(device),
            "dns_events": dns_events,
            "flow_events": flow_events,
            "summary": {
                "unique_domains": device["unique_domains"],
                "unique_destinations": device["unique_destinations"],
                "total_bytes": device["total_bytes"],
                "activity_window": f"{device['first_activity']} to {device['last_activity']}"
            }
        }
    
    def get_all_device_timelines(self, hours=24):
        """Generate timelines for all devices"""
        self.cursor.execute("SELECT device_id FROM devices ORDER BY last_seen DESC")
        devices = [row[0] for row in self.cursor.fetchall()]
        
        timelines = {}
        for device_id in devices:
            timelines[device_id] = self.get_device_timeline(device_id, hours)
        
        return timelines
    
    def detect_suspicious_activity(self, device_id):
        """Detect behavioral anomalies"""
        alerts = []
        
        # Check for DoH usage
        self.cursor.execute("""
            SELECT COUNT(*) as doh_count FROM flows
            WHERE device_id = ? AND is_doh = 1
        """, (device_id,))
        
        if self.cursor.fetchone()[0] > 0:
            alerts.append({
                "type": "doh_detected",
                "severity": "medium",
                "description": "Device using encrypted DNS (DoH/QUIC)"
            })
        
        # Check for blocked domains
        self.cursor.execute("""
            SELECT COUNT(*) as blocked_count, 
                   GROUP_CONCAT(DISTINCT queried_domain) as domains
            FROM dns_queries
            WHERE device_id = ? AND is_blocked = 1
        """, (device_id,))
        
        result = self.cursor.fetchone()
        if result[0] > 10:
            alerts.append({
                "type": "excessive_blocked_queries",
                "severity": "low",
                "count": result[0],
                "sample_domains": (result[1] or "").split(",")[:5]
            })
        
        # Check for rare ASNs (potential VPN)
        self.cursor.execute("""
            SELECT asn, asn_name, COUNT(*) as count
            FROM flows
            WHERE device_id = ?
            GROUP BY asn
            ORDER BY count DESC
        """, (device_id,))
        
        asns = self.cursor.fetchall()
        if len(asns) > 5:
            alerts.append({
                "type": "multiple_vpn_suspects",
                "severity": "high",
                "asn_count": len(asns),
                "asns": [{"asn": a[0], "name": a[1], "flow_count": a[2]} for a in asns[:10]]
            })
        
        return alerts
    
    def export_timeline_json(self, device_id, output_file=None):
        """Export device timeline as JSON"""
        timeline = self.get_device_timeline(device_id, hours=168)  # 1 week
        if not timeline:
            print(f"[-] Device not found: {device_id}")
            return
        
        alerts = self.detect_suspicious_activity(device_id)
        timeline["alerts"] = alerts
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(timeline, f, indent=2, default=str)
            print(f"[+] Timeline exported: {output_file}")
        else:
            print(json.dumps(timeline, indent=2, default=str))
    
    def close(self):
        self.conn.close()

def main():
    builder = DeviceTimeline()
    
    if len(sys.argv) > 1:
        device_id = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        builder.export_timeline_json(device_id, output_file)
    else:
        # Export all device timelines
        timelines = builder.get_all_device_timelines(hours=24)
        
        output_dir = Path("/var/log/mod-router/timelines")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for device_id, timeline in timelines.items():
            if timeline:
                output_file = output_dir / f"{device_id}_{datetime.utcnow().isoformat()}.json"
                with open(output_file, 'w') as f:
                    json.dump(timeline, f, indent=2, default=str)
                print(f"[+] {output_file}")
    
    builder.close()

if __name__ == "__main__":
    main()
EOFPYTHON

chmod +x "$DATADIR/device-timeline-builder.py"

# === ASN/IP ENRICHMENT ===
cat > "$DATADIR/asn-enrichment.py" << 'EOFPYTHON'
#!/usr/bin/env python3
"""
ASN enrichment: enrich flows with MaxMind GeoIP/ASN data
"""

import sqlite3
import json
import sys
import requests
from pathlib import Path

DB_PATH = "/opt/mod-router/mod-router.db"
GEOIP_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False
    print("[-] Warning: geoip2 module not found. Install: pip install geoip2")

def get_asn_from_ip(ip_addr):
    """Get ASN for IP address using MaxMind or WHOIS"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check cache
    cursor.execute("SELECT asn, asn_name, country_code FROM asn_cache WHERE ip_addr = ?", (ip_addr,))
    cached = cursor.fetchone()
    if cached:
        conn.close()
        return {"asn": cached[0], "name": cached[1], "country": cached[2]}
    
    result = None
    
    # Try MaxMind
    if HAS_GEOIP and Path(ASN_DB).exists():
        try:
            with geoip2.database.open_database(ASN_DB) as reader:
                response = reader.asn(ip_addr)
                result = {
                    "asn": response.autonomous_system_number,
                    "name": response.autonomous_system_organization,
                    "country": "unknown"
                }
        except Exception as e:
            pass
    
    # Fallback: ASN lookup API
    if not result:
        try:
            resp = requests.get(f"https://asn.cymru.com/cgi-bin/asn.cgi?ip={ip_addr}&format=json", timeout=5)
            data = resp.json()
            if data:
                result = {
                    "asn": data[0].get("asn", "unknown"),
                    "name": data[0].get("asn_name", "unknown"),
                    "country": data[0].get("asn_country_code", "unknown")
                }
        except:
            pass
    
    # Cache result
    if result:
        cursor.execute("""
            INSERT OR REPLACE INTO asn_cache (ip_addr, asn, asn_name, country_code)
            VALUES (?, ?, ?, ?)
        """, (ip_addr, result["asn"], result["name"], result["country"]))
        conn.commit()
    
    conn.close()
    return result

def enrich_all_flows():
    """Enrich all flows with ASN data"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT DISTINCT dst_ip FROM flows WHERE asn IS NULL LIMIT 1000")
    ips = [row[0] for row in cursor.fetchall()]
    
    count = 0
    for ip in ips:
        asn_info = get_asn_from_ip(ip)
        if asn_info:
            cursor.execute("""
                UPDATE flows SET asn = ?, geo_country = ?
                WHERE dst_ip = ?
            """, (f"AS{asn_info['asn']}", asn_info['country'], ip))
            count += 1
    
    conn.commit()
    print(f"[+] Enriched {count} flows with ASN data")
    conn.close()

if __name__ == "__main__":
    enrich_all_flows()
EOFPYTHON

chmod +x "$DATADIR/asn-enrichment.py"

# === INCIDENT REPORT GENERATOR ===
cat > "$DATADIR/incident-report.py" << 'EOFPYTHON'
#!/usr/bin/env python3
"""
Generate forensic incident reports with evidence
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
import sys

DB_PATH = "/opt/mod-router/mod-router.db"

def generate_incident_report(incident_id):
    """Generate detailed incident report with forensic evidence"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get incident
    cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    incident = cursor.fetchone()
    if not incident:
        print(f"[-] Incident not found: {incident_id}")
        return
    
    # Get device info
    cursor.execute("SELECT * FROM devices WHERE device_id = ?", (incident["device_id"],))
    device = cursor.fetchone()
    
    # Get related flows
    cursor.execute("""
        SELECT * FROM flows WHERE device_id = ? 
        ORDER BY timestamp DESC LIMIT 100
    """, (incident["device_id"],))
    flows = [dict(row) for row in cursor.fetchall()]
    
    # Get DNS queries around incident time
    cursor.execute("""
        SELECT * FROM dns_queries WHERE device_id = ? 
        AND datetime(timestamp) >= datetime(?, '-5 minutes')
        AND datetime(timestamp) <= datetime(?, '+5 minutes')
        ORDER BY timestamp DESC
    """, (incident["device_id"], incident["timestamp"], incident["timestamp"]))
    dns_queries = [dict(row) for row in cursor.fetchall()]
    
    report = {
        "report_generated": datetime.utcnow().isoformat(),
        "incident": dict(incident),
        "device": dict(device),
        "evidence": {
            "related_flows": flows,
            "dns_queries_5min_window": dns_queries,
        }
    }
    
    return report

def main():
    if len(sys.argv) > 1:
        incident_id = int(sys.argv[1])
        report = generate_incident_report(incident_id)
        
        if report:
            # Save to file
            output_file = f"/var/log/mod-router/incident-{incident_id}-{datetime.utcnow().isoformat()}.json"
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report: {output_file}")
            print(json.dumps(report, indent=2, default=str))
    else:
        print("Usage: incident-report.py <incident_id>")

if __name__ == "__main__":
    main()
EOFPYTHON

chmod +x "$DATADIR/incident-report.py"

# === WIRESHARK/TCPDUMP HELPER ===
cat > "$DATADIR/pcap-exporter.sh" << 'EOFSH'
#!/bin/bash
# Export PCAP for incident forensics (Wireshark/tcpdump)

DEVICE_ID="${1:-}"
START_TIME="${2:-}"
END_TIME="${3:-}"
OUTPUT_FILE="${4:-/var/lib/mod-router/export.pcap}"

if [ -z "$DEVICE_ID" ]; then
    echo "Usage: pcap-exporter.sh <device_id> [start_time] [end_time] [output_file]"
    echo "Example: pcap-exporter.sh MAC_AA_BB_CC_DD_EE '2025-01-21 10:00:00' '2025-01-21 10:05:00'"
    exit 1
fi

# Get device IP from database
IP=$(sqlite3 /opt/mod-router/mod-router.db "SELECT ipv4_addr FROM devices WHERE device_id LIKE '%$DEVICE_ID%' LIMIT 1")

if [ -z "$IP" ]; then
    echo "[-] Device not found: $DEVICE_ID"
    exit 1
fi

echo "[*] Exporting PCAP for $DEVICE_ID ($IP)..."

# Build tcpdump filter
FILTER="src host $IP or dst host $IP"
if [ -n "$START_TIME" ] && [ -n "$END_TIME" ]; then
    FILTER="$FILTER and time between '$START_TIME' and '$END_TIME'"
fi

# Export from archived PCAPs
mergecap -w "$OUTPUT_FILE" /var/lib/mod-router/pcaps/*.pcap.gz 2>/dev/null || true
tcpdump -r "$OUTPUT_FILE" "$FILTER" -w "${OUTPUT_FILE}.filtered" 2>/dev/null

echo "[+] Filtered PCAP: ${OUTPUT_FILE}.filtered"
echo "[+] Open in Wireshark: wireshark ${OUTPUT_FILE}.filtered"
EOFSH

chmod +x "$DATADIR/pcap-exporter.sh"

# === CRON: CONTINUOUS ENRICHMENT ===
cat > "$DATADIR/cron-enrich.sh" << 'EOFCRON'
#!/bin/bash
# Periodic ASN enrichment and timeline building

python3 /opt/mod-router/asn-enrichment.py
python3 /opt/mod-router/device-timeline-builder.py
EOFCRON

chmod +x "$DATADIR/cron-enrich.sh"

(crontab -l 2>/dev/null; echo "0 */6 * * * /opt/mod-router/cron-enrich.sh") | crontab -

echo "[+] Device timeline system built!"
echo "[+] Tools installed:"
echo "    - device-timeline-builder.py: Per-device behavioral profiles"
echo "    - asn-enrichment.py: IP → ASN ownership mapping"
echo "    - incident-report.py: Forensic incident reports with evidence"
echo "    - pcap-exporter.sh: Export PCAPs for Wireshark analysis"
echo ""
echo "[+] Quick start:"
echo "    python3 /opt/mod-router/device-timeline-builder.py              # Build all timelines"
echo "    python3 /opt/mod-router/device-timeline-builder.py MAC_1234     # Single device"
echo "    python3 /opt/mod-router/incident-report.py 1                    # Forensic evidence"
