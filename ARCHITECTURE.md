# MOD-ROUTER Architecture & Deployment Guide

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NETWORK CLIENTS                              │
│  (Devices querying DNS, sending flows, browsing)                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                │                     │
                ▼                     ▼
    ┌─────────────────────┐  ┌──────────────────────┐
    │  dnsmasq (port 53)  │  │  Zeek (packet tap)   │
    │  - Blocking         │  │  - Flow analysis     │
    │  - DHCP server      │  │  - TLS metadata      │
    │  - Pi-hole equiv.   │  │  - DNS logging       │
    └──────────┬──────────┘  │  - QUIC detection    │
               │              │  - DoH detection     │
               ▼              └──────────┬───────────┘
    ┌─────────────────────┐             │
    │ Unbound (port 5353) │             │
    │ - Recursive resolver│             │
    │ - DNSSEC validation │             ▼
    │ - Full query logging│   ┌──────────────────┐
    │ - Result caching    │   │  JSON Flow Logs  │
    └──────────┬──────────┘   │  (structured)    │
               │               └────────┬─────────┘
               ▼                        │
    ┌─────────────────────┐            │
    │  Knot Resolver      │            ▼
    │  (port 5354)        │  ┌──────────────────────────┐
    │  - Fallback cache   │  │  SQLite Database         │
    │  - Performance      │  │  ├─ devices             │
    └─────────────────────┘  │  ├─ dns_queries         │
                             │  ├─ flows               │
                             │  ├─ incidents           │
                             │  └─ asn_cache           │
                             └───────┬──────────────────┘
                                     │
        ┌────────────────────────────┼─────────────────────────┐
        │                            │                         │
        ▼                            ▼                         ▼
┌──────────────────┐    ┌──────────────────────┐  ┌──────────────────┐
│ Device Timeline  │    │  ASN Enrichment      │  │ Incident Reports │
│ Builder          │    │  (IP → ownership)    │  │ + Forensics      │
│ - Per-device     │    │  - MaxMind GeoIP     │  │ - PCAP export    │
│   profiles       │    │  - WHOIS lookups     │  │ - Wireshark data │
│ - Behavioral     │    │  - VPN detection     │  │ - Evidence chain │
│   analysis       │    │  - Caching           │  │ - Timeline recon │
└──────────────────┘    └──────────────────────┘  └──────────────────┘
        │
        ▼
┌──────────────────────────────────────────────┐
│  DoH/VPN Detection Engine                     │
│  ├─ Detect DoH endpoints (port 443, 853)    │
│  ├─ Block known DoH IPs via nftables         │
│  ├─ Flag multi-ASN routing (VPN)            │
│  ├─ Alert on QUIC DNS usage                  │
│  └─ Generate forensic alerts                 │
└──────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────┐
│  Optional: MITM Lab Mode (Authorized)         │
│  ├─ mitmproxy (transparent interception)     │
│  ├─ CA cert injection for testing             │
│  ├─ Certificate pinning bypass                │
│  ├─ Payload analysis + malware testing        │
│  └─ Secure lab environment only               │
└──────────────────────────────────────────────┘
```

## Data Flow

### 1. DNS Query Path
```
Client → dnsmasq:53 (block/allow) → Unbound:5353 (recursive) 
  → Upstream (1.1.1.1, 8.8.8.8, etc.) 
  → Response logged to DB + Zeek logs
  → Client receives result (or blocked)
```

### 2. Flow Analysis Path
```
All traffic on interface
  → Zeek packet capture (policies)
  → Extract: src, dst, port, protocol, bytes, timing
  → Log TLS metadata (JA3, SNI) + QUIC detection
  → JSON flow logs to disk
  → Correlate with device (MAC → IP → timeline)
  → Enrich with ASN/GeoIP
  → Store in SQLite flows table
```

### 3. Device Timeline Path
```
DHCP lease (/var/lib/dnsmasq/dhcp.leases)
  → Parse + sync to devices table
DNS queries (dnsmasq/Unbound logs)
  → Parse + correlate with MAC/IP
  → Insert to dns_queries table
Flows (Zeek output)
  → Parse + correlate with device
  → Insert to flows table
  → Trigger ASN enrichment + alert rules
  → Generate per-device behavioral timeline
```

### 4. Forensic Reconstruction Path
```
Incident detected (DoH, malware, unusual traffic, etc.)
  → Create incident record + timestamp
  → Query flows table (±5min window around incident)
  → Query DNS queries (±5min window)
  → Extract related PCAPs (Arkime/tcpdump)
  → Generate incident report (JSON)
  → Export to Wireshark (pcap) for analyst
  → Timeline reconstruction + evidence chain
```

## Installation Stages

### Stage 0: System Prerequisites
```
- Install: zeek, suricata, dnsmasq, dnsutils, net-tools, tcpdump, tshark
- Python 3.9+, pip packages: geoip2, dpkt, scapy, pyyaml, requests
- Create: /var/log/mod-router, /opt/mod-router, /var/lib/mod-router/pcaps
- Initialize: SQLite database with 6 tables + views
```

### Stage 1: Zeek Configuration
```
- Deploy Zeek policies (mod-router.zeek, custom-logging.zeek)
- Configure node.cfg for standalone mode on eth0
- Set up JSON output format for flows
- Enable DNS, TLS, QUIC, DoH detection policies
```

### Stage 2: DNS Authority Stack
```
- Deploy Unbound: recursive resolver on :5353
- Deploy dnsmasq: primary DNS on :53 + DHCP server
- Deploy Knot Resolver: fallback on :5354
- Configure query logging to /var/log/mod-router/
- Build initial blocklist from adlists
- Set up cron: sync DHCP leases every 5 minutes
```

### Stage 3: Device Timeline System
```
- Deploy device-timeline-builder.py
- Deploy asn-enrichment.py
- Deploy incident-report.py
- Set up cron: enrich + timeline every 6 hours
- Test: build timelines for all devices
```

### Stage 4: DoH Detection
```
- Deploy Zeek DoH detection policy
- Deploy DoH analyzer (doh-analyzer.py)
- Configure nftables rules to block DoH
- Test: flag DoH usage on lab devices
```

### Stage 5: MITM Lab (Optional)
```
- Generate root CA certificate
- Deploy mitmproxy config + addon
- Deploy Squid proxy config
- Deploy CA cert installation helper
- Deploy transparent proxy setup
- Document legal/security requirements
```

## Configuration Files

### Zeek Policies
- **`zeek/policies/mod-router.zeek`**: Main policy (DNS, TLS, QUIC, DoH)
- **`zeek/policies/custom-logging.zeek`**: JSON output formatting
- **`zeek/node.cfg`**: Zeek node configuration
- **`zeek/zeekctl.cfg`**: Zeek cluster config

### DNS Configuration
- **`/etc/unbound/conf.d/mod-router.conf`**: Unbound resolver config
- **`/etc/dnsmasq.d/mod-router.conf`**: dnsmasq DNS + DHCP config
- **`/etc/knot-resolver/kresd.conf`**: Knot Resolver fallback config

### Database Schema
- **`devices`**: MAC, IP, hostname, DHCP lease, device type, first/last seen
- **`dns_queries`**: timestamp, device, domain, response IPs, TTL, blocked flag
- **`flows`**: src/dst IP:port, protocol, bytes, duration, JA3, SNI, ASN, GeoIP
- **`asn_cache`**: IP → ASN, provider name, country
- **`doh_indicators`**: Known DoH endpoints (IP, provider)
- **`incidents`**: event_type, device, description, severity, related_flows

### Log Directory Structure
```
/var/log/mod-router/
├── dnsmasq-queries.log      (dnsmasq DNS queries)
├── unbound-queries.log       (Unbound resolver queries)
├── zeek/                     (Zeek output)
│   ├── dns-forensics
│   ├── tls-metadata
│   └── quic-flows
├── timelines/                (Device timeline JSONs)
└── incidents/                (Incident reports)
```

### Data Storage
```
/opt/mod-router/
├── mod-router.db             (SQLite database)
├── mod-router.db.backup      (Backup)
├── parse-dhcp-leases.py      (DHCP sync)
├── parse-dns-logs.py         (DNS log parser)
├── device-timeline-builder.py
├── asn-enrichment.py
├── incident-report.py
├── doh-analyzer.py
├── pcap-exporter.sh
├── block-doh.sh
├── mitm-lab/                 (MITM lab files)
│   ├── certs/
│   │   ├── mod-router-ca.pem
│   │   └── mod-router-ca.key
│   ├── mitmproxy-config.py
│   ├── squid.conf
│   ├── logs/
│   └── pcaps/
└── doh-blocklist.txt
```

## Deployment Commands (Copy/Paste Ready)

### Full Stack (One Command)
```bash
cd /home/mdx/mod-router && bash scripts/full-deploy.sh
```

### Individual Components
```bash
# Phase 0: Initialize
bash scripts/00-deploy-stack.sh

# Phase 1: Zeek
bash scripts/01-zeek-config.sh

# Phase 2: DNS
bash scripts/02-dns-authority.sh

# Phase 3: Timelines
bash scripts/03-device-timeline.sh

# Phase 4: DoH Detection
bash scripts/04-doh-detection.sh

# Phase 5: MITM Lab (optional)
bash scripts/05-mitm-lab-setup.sh

# Phase 6: Validation
bash scripts/06-integration-tests.sh
```

## Performance Characteristics

### Storage
- **DNS Queries**: ~1 KB per query (2-5 GB/month @ 1000 queries/min)
- **Flows**: ~300 bytes per flow (1-2 GB/month @ 10K flows/day)
- **PCAPs**: ~1 MB/min uncompressed (compress to 100-200 KB/min)
- **Database**: ~5-10 MB/month indexed
- **Total**: ~5-10 GB/month with compression, long-term (years) feasible on 1-2 TB storage

### Processing
- **DNS Resolution**: <5ms (Unbound cached)
- **Zeek Flow Processing**: <1ms per packet
- **Device Timeline Building**: <2 seconds (1000 devices)
- **ASN Enrichment**: 1-2 seconds per 1000 IPs
- **PCAP Export**: <5 seconds for 24-hour window

### Retention
- **Real-time**: 100% (all queries/flows)
- **1 month**: Compressed logs (50% reduction)
- **3 months+**: Sampled flows (10% sampling) + DNS queries (full)
- **1 year+**: Incident reports + high-level statistics only

## Security Considerations

### DNS Authority
- ✅ DNSSEC validation enabled
- ✅ Query logging for forensics
- ✅ DoH/encrypted DNS blocking
- ✅ Private network isolation (192.168.x, 10.x, 172.16.x)

### Flow Logging
- ✅ TLS metadata extracted (no keys)
- ⚠️ Unencrypted traffic visible (log with caution in regulated environments)
- ✅ ASN enrichment anonymized (no payload)

### Device Tracking
- ✅ MAC address used as device ID (pseudonymized)
- ⚠️ DHCP leases may contain real hostnames
- ✅ Timeline built from DNS/flow data (not packet inspection)

### MITM Lab
- ❌ ONLY in isolated lab environment
- ❌ Requires explicit authorization
- ⚠️ Breaks app security, certificate pinning
- ⚠️ Exposes session tokens, credentials, personal data
- **Legal**: May violate wiretapping, GDPR, HIPAA laws

## Compliance & Regulations

| Regulation | Compliance | Notes |
|-----------|-----------|-------|
| **GDPR** | ⚠️ Partial | Device IDs pseudonymized; DNS queries may contain PII |
| **HIPAA** | ❌ No | Query logs may contain health-related domains |
| **PCI-DSS** | ⚠️ Limited | Flow logs don't capture payment data; MITM violates compliance |
| **SOC2** | ⚠️ Conditional | OK for authorized security testing; flag unauthorized access |
| **Wiretap Laws** | ❌ MITM illegal | DNS/flow logging OK; MITM interception requires consent |

## Incident Response Playbook

### 1. Detect Incident (Alert)
```bash
# Triggered by: DoH usage, malware signature, unusual pattern, etc.
sqlite3 /opt/mod-router/mod-router.db "INSERT INTO incidents ..."
```

### 2. Extract Timeline
```bash
python3 /opt/mod-router/device-timeline-builder.py MAC_1234 /tmp/timeline.json
```

### 3. Generate Forensic Report
```bash
python3 /opt/mod-router/incident-report.py 1  # Incident ID
```

### 4. Export PCAP
```bash
bash /opt/mod-router/pcap-exporter.sh MAC_1234 '2025-01-21 10:00' '2025-01-21 10:05'
```

### 5. Analyze in Wireshark
```bash
wireshark /var/lib/mod-router/export.pcap.filtered
```

### 6. Document Evidence
```bash
# All evidence captured in incident report JSON + PCAP + timeline
# Ready for forensic analysis + expert testimony
```
