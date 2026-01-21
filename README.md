# MOD-ROUTER: Desktop-as-Router Forensic Audit Stack

## Overview
Comprehensive DNS + network forensics pipeline for device tracking, DoH detection, behavioral analysis, and incident reconstruction.

### Components
- **DNS Authority**: Pi-hole (blocking) + Unbound (recursive resolver) + Knot Resolver (fallback)
- **Flow Analysis**: Zeek (connection metadata) + Arkime (PCAP indexing/retrieval)
- **Device Tracking**: DHCP lease correlation, per-device behavioral timelines
- **DoH Detection**: Block known DoH endpoints, detect encrypted DNS
- **Log Retention**: JSON flow schemas, compression, long-term storage
- **ASN Enrichment**: MaxMind GeoIP/ASN attribution

### Quick Start
```bash
cd /home/mdx/mod-router
./scripts/00-deploy-stack.sh          # Deploy all services
./scripts/01-zeek-config.sh           # Configure Zeek policies
./scripts/02-dns-authority.sh         # Deploy DNS stack
./scripts/03-device-timeline.sh       # Build device behavioral profiles
```

### Forensic Capabilities
- Per-device DNS query timelines with IP ownership
- Flow-based incident reconstruction (Wireshark/tcpdump)
- DoH/VPN detection and blocking
- TLS metadata extraction (JA3 fingerprints, SNI)
- Long-term retention (months-to-years, compressed)
- MITM lab mode for controlled testing
