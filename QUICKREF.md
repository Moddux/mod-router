# MOD-ROUTER Quick Reference

## Install & Deploy

```bash
cd /home/mdx/mod-router

# Full stack deployment (one command)
bash scripts/full-deploy.sh

# Or deploy individual components
bash scripts/00-deploy-stack.sh           # Initialize
bash scripts/01-zeek-config.sh            # Zeek policies
bash scripts/02-dns-authority.sh          # DNS stack
bash scripts/03-device-timeline.sh        # Device tracking
bash scripts/04-doh-detection.sh          # DoH detection
bash scripts/05-mitm-lab-setup.sh         # MITM testing (optional)
bash scripts/06-integration-tests.sh      # Validate
```

## DNS Authority

### Port Mapping
- **Port 53**: dnsmasq (primary DNS + blocking)
- **Port 5353**: Unbound (recursive resolver)
- **Port 5354**: Knot Resolver (fallback)

### Query DNS
```bash
# Query dnsmasq (primary)
dig @127.0.0.1 -p 53 example.com

# Query Unbound
dig @127.0.0.1 -p 5353 example.com

# Query Knot Resolver
dig @127.0.0.1 -p 5354 example.com
```

### View DNS Logs
```bash
# dnsmasq query log
tail -f /var/log/mod-router/dnsmasq-queries.log

# Unbound query log
tail -f /var/log/mod-router/unbound-queries.log

# View parsed queries in database
sqlite3 /opt/mod-router/mod-router.db "SELECT * FROM dns_queries ORDER BY timestamp DESC LIMIT 20;"
```

## Zeek Network Forensics

### Start Zeek
```bash
# Run with MOD-ROUTER policies
sudo bash scripts/zeek-runner.sh eth0

# Manual start
sudo zeek -i eth0 \
  -L /home/mdx/mod-router/zeek/policies/mod-router.zeek \
  --logdir /var/log/mod-router/zeek
```

### View Zeek Logs
```bash
# DNS forensics
tail -f /var/log/mod-router/zeek/dns-forensics

# TLS metadata (JA3, SNI)
tail -f /var/log/mod-router/zeek/tls-metadata

# QUIC flows
tail -f /var/log/mod-router/zeek/quic-flows
```

### Export flows to JSON
```bash
zeek-cut id.orig_h id.resp_h id.resp_p proto duration conn_state \
  < /var/log/mod-router/zeek/conn.log > /tmp/flows.json
```

## Device Behavioral Timeline

### Build Per-Device Timeline
```bash
# All devices (last 24 hours)
python3 /opt/mod-router/device-timeline-builder.py

# Specific device
python3 /opt/mod-router/device-timeline-builder.py MAC_AA_BB_CC_DD_EE

# Export to JSON
python3 /opt/mod-router/device-timeline-builder.py MAC_1234 /tmp/device-timeline.json
```

### View Devices
```bash
sqlite3 /opt/mod-router/mod-router.db "SELECT device_id, mac_addr, ipv4_addr, hostname, device_type FROM devices;"
```

### View DNS Query Timeline
```bash
sqlite3 /opt/mod-router/mod-router.db << 'EOF'
SELECT 
  d.hostname,
  d.ipv4_addr,
  dns.timestamp,
  dns.queried_domain,
  dns.response_ips,
  dns.is_blocked
FROM devices d
LEFT JOIN dns_queries dns ON d.device_id = dns.device_id
WHERE d.device_id LIKE 'MAC%'
ORDER BY dns.timestamp DESC
LIMIT 50;
EOF
```

## DoH/VPN Detection

### Scan All Devices for DoH Usage
```bash
# Generate DoH detection report
python3 /opt/mod-router/doh-analyzer.py > /tmp/doh-report.json

# View results
jq '.' /tmp/doh-report.json
```

### Detect Specific Device
```bash
python3 /opt/mod-router/doh-analyzer.py MAC_AA_BB_CC_DD_EE
```

### Block DoH Endpoints
```bash
# Deploy nftables rules to block known DoH IPs
bash /opt/mod-router/block-doh.sh

# View rules
sudo nft list table inet doh_block
```

### Query DoH Indicators
```bash
sqlite3 /opt/mod-router/mod-router.db << 'EOF'
-- Find flows to known DoH providers
SELECT device_id, dst_ip, COUNT(*) as flow_count
FROM flows
WHERE dst_ip IN ('1.1.1.1', '1.0.0.1', '8.8.8.8', '9.9.9.9')
  AND dst_port = 443
GROUP BY device_id, dst_ip;

-- Find QUIC/UDP 443 (DNS-over-QUIC)
SELECT device_id, COUNT(*) as quic_count
FROM flows
WHERE dst_port = 443 AND protocol IN ('quic', 'udp')
GROUP BY device_id;
EOF
```

## PCAP/Wireshark Analysis

### Export PCAP for Specific Device
```bash
# Export 5-minute window around incident
bash /opt/mod-router/pcap-exporter.sh MAC_AA_BB_CC_DD_EE \
  '2025-01-21 10:00:00' \
  '2025-01-21 10:05:00' \
  /tmp/device-forensics.pcap

# Open in Wireshark
wireshark /tmp/device-forensics.pcap.filtered
```

### Extract DNS Queries from PCAP
```bash
tshark -r /var/lib/mod-router/pcaps/*.pcap -Y 'dns' \
  -T fields -e dns.qry.name -e dns.resp.addr | sort -u
```

### Extract TLS SNI (Server Names)
```bash
tshark -r /var/lib/mod-router/pcaps/*.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e tls.handshake.extensions_server_name | sort -u
```

### Extract JA3 Fingerprints
```bash
tshark -r /var/lib/mod-router/pcaps/*.pcap -Y 'ssl.handshake.type == 1' \
  -T fields -e ip.src -e tls.handshake.ciphersuite | head -20
```

## Incident Forensics

### Generate Forensic Report
```bash
# List all incidents
sqlite3 /opt/mod-router/mod-router.db "SELECT incident_id, device_id, incident_type, timestamp FROM incidents;"

# Generate detailed report for incident #1
python3 /opt/mod-router/incident-report.py 1

# Report includes: device info, related flows, DNS queries, evidence
```

### Query Incidents by Type
```bash
sqlite3 /opt/mod-router/mod-router.db << 'EOF'
SELECT * FROM incidents 
WHERE incident_type IN ('DoH_Detected', 'doh_detected', 'suspicious_asn')
ORDER BY timestamp DESC;
EOF
```

## ASN/IP Enrichment

### Enrich Flows with ASN Data
```bash
# Run enrichment
python3 /opt/mod-router/asn-enrichment.py

# Query by ASN
sqlite3 /opt/mod-router/mod-router.db << 'EOF'
SELECT DISTINCT asn, asn_name, COUNT(*) as flow_count
FROM flows
WHERE device_id = 'MAC_1234'
GROUP BY asn
ORDER BY flow_count DESC;
EOF
```

### Find VPN Usage
```bash
sqlite3 /opt/mod-router/mod-router.db << 'EOF'
-- Devices routing through multiple ASNs (VPN indicator)
SELECT device_id, COUNT(DISTINCT asn) as unique_asns
FROM flows
GROUP BY device_id
HAVING unique_asns > 10
ORDER BY unique_asns DESC;
EOF
```

## MITM Lab Mode (Testing Only)

### Install CA on Test Device
```bash
# Copy and install certificate
bash /opt/mod-router/mitm-lab/install-ca-on-device.sh 192.168.1.100
```

### Start MITM Interception
```bash
# Start mitmproxy
bash /opt/mod-router/mitm-lab/start-mitmproxy.sh

# mitmproxy running on 0.0.0.0:8080
# Point device proxy settings to router:8080
```

### Analyze MITM Traffic
```bash
# Extract URLs from intercepted traffic
bash /opt/mod-router/mitm-lab/analyze-pcaps.sh

# View logs
ls -la /opt/mod-router/mitm-lab/logs/
```

## Database Maintenance

### Backup Database
```bash
cp /opt/mod-router/mod-router.db /opt/mod-router/mod-router.db.backup
```

### Compress Old Logs (Monthly Retention)
```bash
find /var/log/mod-router -name '*.log' -mtime +30 -exec gzip {} \;
```

### Query Summary Statistics
```bash
sqlite3 /opt/mod-router/mod-router.db << 'EOF'
-- Total devices tracked
SELECT COUNT(*) as total_devices FROM devices;

-- DNS queries in last 24h
SELECT COUNT(*) as queries_24h FROM dns_queries 
WHERE timestamp > datetime('now', '-1 day');

-- Blocked queries
SELECT COUNT(*) as blocked_queries FROM dns_queries WHERE is_blocked = 1;

-- Unique domains queried
SELECT COUNT(DISTINCT queried_domain) as unique_domains FROM dns_queries;

-- Flow summary
SELECT COUNT(*) as total_flows, 
       SUM(bytes_in + bytes_out) as total_bytes FROM flows;
EOF
```

## Troubleshooting

### DNS not responding
```bash
# Check services
systemctl status dnsmasq unbound knot-resolver

# Restart DNS stack
sudo systemctl restart dnsmasq unbound knot-resolver

# Verify port listening
sudo netstat -tulpn | grep -E ':(53|5353|5354)'
```

### Zeek not capturing
```bash
# Check interface
ip link show | grep UP

# Test capture
sudo tcpdump -i eth0 -c 5

# Restart Zeek
sudo pkill -f zeek || true
```

### Database errors
```bash
# Check database integrity
sqlite3 /opt/mod-router/mod-router.db "PRAGMA integrity_check;"

# Rebuild if corrupted
sqlite3 /opt/mod-router/mod-router.db "VACUUM;"
```

### Performance tuning
```bash
# Increase Unbound cache
# Edit /etc/unbound/conf.d/mod-router.conf
# cache-max-ttl: 604800  # 1 week

# Increase dnsmasq cache-size
# Edit /etc/dnsmasq.d/mod-router.conf
# cache-size=50000

# Restart services
sudo systemctl restart unbound dnsmasq
```
