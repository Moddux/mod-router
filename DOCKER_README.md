# MOD-ROUTER Docker Release

**Forensic DNS + Network Audit Stack - Production-Ready Container**

This repository contains a complete, audited, and containerized forensic DNS and network analysis platform suitable for:

- **Network forensics labs**
- **OSINT research environments**
- **Incident response operations**
- **Offline/controlled-network deployments**
- **Security research and testing**

---

## What is MOD-ROUTER?

MOD-ROUTER is a comprehensive system for:

✅ **DNS Query Logging & Analysis** - Comprehensive DNS logging with device tracking  
✅ **Network Forensics** - Zeek-powered connection logging, TLS metadata extraction, QUIC detection  
✅ **Device Behavioral Profiles** - Correlate DNS + flows with device identities  
✅ **DoH/VPN Detection** - Identify encrypted DNS and VPN usage patterns  
✅ **Incident Response** - Generate forensic reports with evidence reconstruction  
✅ **Long-term Retention** - Efficient storage of network telemetry (months-to-years)

---

## Quick Start

### 1. Build Docker Image

```bash
git clone https://github.com/Moddux/mod-router.git
cd mod-router
docker build -t mod-router:latest .
```

**Build time:** ~5 minutes  
**Image size:** ~500MB

### 2. Run with Docker Compose

```bash
# Start all services
docker-compose up -d

# Verify
docker-compose ps
docker-compose logs mod-router
```

### 3. Test DNS Services

```bash
# Query primary DNS (port 53)
dig @127.0.0.1 -p 53 example.com

# Query recursive resolver (port 5353)
dig @127.0.0.1 -p 5353 example.com

# Inside container
docker exec mod-router dig @127.0.0.1 example.com
```

### 4. Generate Forensic Reports

```bash
# Build device behavioral timelines
docker exec mod-router python3 /opt/mod-router/device-timeline-builder.py

# Scan for DoH/VPN usage
docker exec mod-router python3 /opt/mod-router/doh-analyzer.py

# Generate incident report
docker exec mod-router python3 /opt/mod-router/incident-report.py 1
```

---

## What's Included

### Core Services

| Service | Port | Purpose | Technology |
|---------|------|---------|---|
| **dnsmasq** | 53 (UDP/TCP) | Primary DNS + query blocking | dnsmasq 2.85+ |
| **Unbound** | 5353 (TCP) | Recursive resolver + DNSSEC | Unbound 1.13+ |
| **Knot Resolver** | 5354 (UDP) | Fallback cache resolver | Knot 6.0+ |
| **Zeek** | Network tap | Packet capture + flow analysis | Zeek 5.0+ |

### Python Utilities (Embedded)

| Tool | Purpose | CLI Usage |
|------|---------|-----------|
| **device-timeline-builder.py** | Device behavioral profiling | `python3 device-timeline-builder.py [device_id]` |
| **asn-enrichment.py** | IP → ASN enrichment | `python3 asn-enrichment.py` |
| **doh-analyzer.py** | DoH/VPN detection | `python3 doh-analyzer.py [device_id]` |
| **incident-report.py** | Forensic incident reports | `python3 incident-report.py <incident_id>` |

### Data Storage

| Component | Location | Purpose |
|-----------|----------|---------|
| **SQLite Database** | `/opt/mod-router/mod-router.db` | Device tracking, DNS queries, flows, incidents |
| **Query Logs** | `/var/log/mod-router/` | dnsmasq, Unbound, Zeek logs |
| **PCAP Archives** | `/var/lib/mod-router/pcaps/` | Network packet captures |
| **Device Profiles** | `/var/log/mod-router/timelines/` | JSON behavioral profiles |

---

## Architecture

### Network Data Flow

```
Network Clients
    ↓
[dnsmasq:53] → DNS blocking/forwarding
    ↓
[Unbound:5353] → Recursive resolution with logging
    ↓
[Zeek] → Packet capture & flow analysis
    ↓
[SQLite Database]
    ├─ devices table
    ├─ dns_queries table
    ├─ flows table
    ├─ asn_cache table
    └─ incidents table
    ↓
[Timeline Builder] → Device behavioral profiles
[DoH Analyzer] → Encrypted DNS detection
[Incident Report] → Forensic evidence reconstruction
```

### Container Architecture

```
Base Image: debian:bookworm-slim (120MB)
    ↓
System packages (zeek, dnsmasq, unbound, Python 3.11)
    ↓
Python virtual environment + pinned dependencies
    ↓
MOD-ROUTER scripts + Zeek policies
    ↓
Non-root user (mod-router:mod-router)
    ↓
Final image: ~500MB
```

---

## Configuration

### Environment Variables

```bash
# Core paths (configurable)
MOD_ROUTER_HOME=/opt/mod-router
MOD_ROUTER_DB=/opt/mod-router/mod-router.db
MOD_ROUTER_LOGS=/var/log/mod-router
MOD_ROUTER_PCAPS=/var/lib/mod-router/pcaps

# DNS tuning
UNBOUND_THREADS=4              # CPU threads for Unbound resolver
DNSMASQ_CACHE_SIZE=10000       # DNS query cache size
DEBUG=0                         # Enable debug logging (0/1)
```

### Volume Mounts

```yaml
volumes:
  # Database persistence
  - mod-router-db:/opt/mod-router

  # Log persistence
  - mod-router-logs:/var/log/mod-router

  # PCAP storage
  - mod-router-pcaps:/var/lib/mod-router/pcaps

  # Optional: Custom configurations
  - ./config/unbound.conf:/etc/unbound/conf.d/mod-router.conf:ro
  - ./config/dnsmasq.conf:/etc/dnsmasq.d/mod-router.conf:ro
```

---

## Usage Examples

### Example 1: Query Forensic Database

```bash
# List all devices
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db \
  "SELECT device_id, mac_addr, ipv4_addr, hostname FROM devices;"

# Recent DNS queries
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db \
  "SELECT timestamp, queried_domain, response_ips FROM dns_queries LIMIT 50;"

# Device with most blocked queries
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db \
  "SELECT device_id, COUNT(*) as blocked_count FROM dns_queries WHERE is_blocked=1 GROUP BY device_id ORDER BY blocked_count DESC;"
```

### Example 2: Generate Device Timeline

```bash
# All devices (last 24 hours)
docker exec mod-router python3 /opt/mod-router/device-timeline-builder.py

# Specific device
docker exec mod-router python3 /opt/mod-router/device-timeline-builder.py MAC_AA_BB_CC_DD_EE

# Export to JSON
docker exec mod-router python3 /opt/mod-router/device-timeline-builder.py \
  MAC_AA_BB_CC_DD_EE /tmp/device-timeline.json
docker cp mod-router:/tmp/device-timeline.json ./device-timeline.json
```

### Example 3: DoH/VPN Detection Report

```bash
# Generate full report
docker exec mod-router python3 /opt/mod-router/doh-analyzer.py > doh-report.json

# Analyze specific device
docker exec mod-router python3 /opt/mod-router/doh-analyzer.py MAC_12_34_56 | jq .

# Extract suspicious devices
jq '.[] | select(.is_doh_user == true or .is_vpn_user == true)' doh-report.json
```

### Example 4: Real-time Query Monitoring

```bash
# Watch live DNS queries
docker exec -it mod-router tail -f /var/log/mod-router/dnsmasq-queries.log

# Query count per minute
docker exec mod-router tail -f /var/log/mod-router/dnsmasq-queries.log | \
  sed 's/ .*//' | sort | uniq -c

# Top queried domains
docker exec mod-router awk '{print $(NF-1)}' /var/log/mod-router/dnsmasq-queries.log | \
  sort | uniq -c | sort -rn | head -20
```

---

## Optional Features

### Network Packet Capture (Zeek)

Enable to capture network packets and extract TLS/QUIC metadata:

```bash
docker-compose --profile zeek up -d

# Monitor Zeek logs
docker-compose logs -f zeek
```

**Requirements:**
- Host network access (uses `--net=host`)
- Elevated capabilities (NET_RAW, NET_ADMIN)
- Interface name must match (default: eth0)

### Device Timeline Builder (Hourly)

Automatically generate device profiles every hour:

```bash
docker-compose --profile timeline up -d
```

### DoH/VPN Detection (Every 30 minutes)

Continuously scan for encrypted DNS usage:

```bash
docker-compose --profile detection up -d
```

### Prometheus Monitoring

Export metrics to Prometheus:

```bash
docker-compose --profile monitoring up -d
```

Metrics exposed on port 9100

---

## Security & Privacy

### Security Features

✅ **Non-root execution** - Runs as dedicated user (mod-router)  
✅ **Capability dropping** - Only required Linux capabilities enabled  
✅ **Read-only where possible** - Configuration files mounted read-only  
✅ **No hardcoded secrets** - All configuration via environment  
✅ **Security audited** - Complete source code audit performed  

### Privacy Considerations

⚠️ **Network telemetry** - All DNS queries and flows are logged  
⚠️ **Device tracking** - DHCP leases correlate IPs to devices  
⚠️ **Data retention** - Implement retention policies per compliance requirements  
⚠️ **MITM lab optional** - Decryption requires explicit consent  

### Legal Notes

- **Authorization required** - Deploy only on networks you own or manage
- **GDPR compliance** - Device tracking may require policy documentation
- **HIPAA/compliance** - Not suitable for regulated data without additional controls
- **Data deletion** - Implement proper data destruction procedures

---

## Troubleshooting

### DNS Not Responding

```bash
# Check if services are running
docker-compose ps

# Verify services started
docker exec mod-router systemctl status dnsmasq
docker exec mod-router systemctl status unbound

# Check logs
docker exec mod-router tail -f /var/log/mod-router/dnsmasq-queries.log
```

### Database Errors

```bash
# Check database
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db "SELECT COUNT(*) FROM devices;"

# Repair if corrupted
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db "PRAGMA integrity_check;"
```

### High Disk Usage

```bash
# Check log sizes
docker exec mod-router du -sh /var/log/mod-router
docker exec mod-router du -sh /var/lib/mod-router/pcaps

# Compress old logs
docker exec mod-router find /var/log/mod-router -mtime +7 -exec gzip {} \;

# Archive PCAPs
docker exec mod-router tar -czf /tmp/pcaps.tar.gz /var/lib/mod-router/pcaps
```

See [DOCKER_DEPLOYMENT_GUIDE.md](DOCKER_DEPLOYMENT_GUIDE.md) for comprehensive troubleshooting.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Original project overview |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design & compliance |
| [QUICKREF.md](QUICKREF.md) | Command reference |
| [DOCKER_AUDIT_REPORT.md](DOCKER_AUDIT_REPORT.md) | Security & audit findings |
| [DOCKER_DEPLOYMENT_GUIDE.md](DOCKER_DEPLOYMENT_GUIDE.md) | Comprehensive deployment guide |
| [Dockerfile](Dockerfile) | Container image definition |
| [docker-compose.yml](docker-compose.yml) | Multi-container orchestration |
| [requirements.txt](requirements.txt) | Python dependencies (pinned) |

---

## Performance Characteristics

### System Requirements

- **CPU:** 2+ cores (4+ recommended)
- **RAM:** 4GB minimum (8GB for 24/7 capture)
- **Disk:** 50GB+ (depends on retention policy)
- **Network:** Direct access to network interface (for Zeek)

### Typical Performance

- **DNS queries:** 10,000+ per minute (single instance)
- **Database size:** ~5-10MB per month (with PCAP retention)
- **Query latency:** <50ms (99th percentile)
- **Log storage:** ~1MB per month (compressed)

### Scaling Considerations

- **Single node:** Suitable for networks up to ~1000 devices
- **Multi-node:** Consider load balancing for >10,000 devices
- **Long-term storage:** Use Elasticsearch or S3 for forensic archive

---

## Contributing

Issues and pull requests welcome: https://github.com/Moddux/mod-router

---

## License

See [LICENSE](LICENSE) file in repository.

---

## Support

- **Documentation:** See docs/ directory
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions

---

**Version:** 1.0.0  
**Last Updated:** January 21, 2026  
**Status:** ✅ Production-Ready

