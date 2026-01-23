# MOD-ROUTER Docker Deployment Guide

**Version:** 1.0.0  
**Date:** January 21, 2026  
**Purpose:** Production-grade deployment of MOD-ROUTER forensic DNS + network audit stack

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Building the Docker Image](#building)
4. [Running with Docker](#running)
5. [Running with Docker Compose](#docker-compose)
6. [Configuration](#configuration)
7. [Data Persistence](#persistence)
8. [Networking](#networking)
9. [Security Considerations](#security)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Deployments](#advanced)
12. [Performance Tuning](#performance)

---

## Quick Start

### Minimal Deployment (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/Moddux/mod-router.git
cd mod-router

# 2. Build Docker image
docker build -t mod-router:latest .

# 3. Run with Docker Compose
docker-compose up -d

# 4. Verify services
docker-compose logs mod-router
docker-compose ps

# 5. Test DNS
docker exec mod-router dig @127.0.0.1 example.com
```

### Access Services

```bash
# Query dnsmasq (port 53)
dig @127.0.0.1 -p 53 example.com

# Query Unbound (port 5353)
dig @127.0.0.1 -p 5353 example.com

# Access container shell
docker exec -it mod-router bash

# View logs
docker-compose logs -f mod-router
```

---

## Prerequisites

### Host System Requirements

- **OS:** Linux (Debian/Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Docker:** 20.10+ (`docker --version`)
- **Docker Compose:** v2.0+ (`docker compose --version`)
- **CPU:** 2+ cores recommended
- **RAM:** 4GB minimum (8GB for production)
- **Disk:** 50GB+ (for PCAP retention)
- **User:** Docker group membership (or sudo access)

### Verify Installation

```bash
# Check Docker
docker --version
docker run hello-world

# Check Docker Compose
docker compose --version

# Check disk space
df -h /var/lib/docker

# Check kernel capabilities
grep -E '^(CAP_NET_RAW|CAP_NET_ADMIN)' /proc/1/status
```

### Linux Kernel Requirements

MOD-ROUTER requires kernel capabilities for packet capture:

```bash
# Enable IP forwarding (required for forensics)
sudo sysctl -w net.ipv4.ip_forward=1
sudo echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# Enable netfilter (for DoH blocking)
sudo modprobe nf_conntrack
sudo modprobe nf_tables
```

---

## Building the Docker Image

### Standard Build

```bash
# Build with default settings
docker build -t mod-router:latest .

# Build with specific tag
docker build -t mod-router:1.0.0 -t mod-router:latest .

# Build with build-time arguments
docker build \
  --build-arg DEBIAN_FRONTEND=noninteractive \
  -t mod-router:production .
```

### Build Optimization

```bash
# Use Docker BuildKit for faster builds (optional)
DOCKER_BUILDKIT=1 docker build -t mod-router:latest .

# Build with progress output
docker build --progress=plain -t mod-router:latest .

# Build and show layer sizes
docker build -t mod-router:latest . && docker history mod-router:latest
```

### Verify Build

```bash
# Check image size
docker images | grep mod-router

# Inspect image
docker inspect mod-router:latest

# Run image test
docker run --rm mod-router:latest python3 --version

# Check installed tools
docker run --rm mod-router:latest zeek --version
docker run --rm mod-router:latest dnsmasq --version
```

---

## Running with Docker

### Standalone Container (without Compose)

#### Minimal Run

```bash
docker run -d \
  --name mod-router \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --cap-add NET_BIND_SERVICE \
  -p 53:53/udp \
  -p 5353:5353/tcp \
  -p 5354:5354/udp \
  -v mod-router-db:/opt/mod-router \
  -v mod-router-logs:/var/log/mod-router \
  mod-router:latest
```

#### Full-Featured Run (with persistence)

```bash
docker run -d \
  --name mod-router \
  --restart unless-stopped \
  
  # Capabilities for forensics
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --cap-add NET_BIND_SERVICE \
  
  # Security
  --security-opt no-new-privileges:true \
  --user mod-router:mod-router \
  
  # Ports
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 5353:5353/tcp \
  -p 5354:5354/udp \
  
  # Volumes
  -v mod-router-db:/opt/mod-router \
  -v mod-router-logs:/var/log/mod-router \
  -v mod-router-pcaps:/var/lib/mod-router/pcaps \
  
  # Environment
  -e MOD_ROUTER_HOME=/opt/mod-router \
  -e UNBOUND_THREADS=4 \
  -e DNSMASQ_CACHE_SIZE=10000 \
  
  # Logging
  --log-driver json-file \
  --log-opt max-size=100m \
  --log-opt max-file=10 \
  
  # Labels
  --label "com.mod-router.component=dns-forensics" \
  --label "com.mod-router.environment=production" \
  
  mod-router:latest
```

### Container Management

```bash
# Check status
docker ps | grep mod-router
docker ps -a | grep mod-router

# View logs
docker logs mod-router
docker logs -f mod-router

# Inspect container
docker inspect mod-router

# Execute commands in container
docker exec -it mod-router bash
docker exec mod-router dig @127.0.0.1 example.com

# Stop container
docker stop mod-router

# Restart container
docker restart mod-router

# Remove container
docker rm mod-router

# Check resource usage
docker stats mod-router
```

---

## Running with Docker Compose

### Standard Deployment

```bash
# Start services in foreground
docker-compose up

# Start services in background
docker-compose up -d

# View logs
docker-compose logs
docker-compose logs -f mod-router

# Check status
docker-compose ps

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Restart single service
docker-compose restart mod-router

# Update image and redeploy
docker-compose pull
docker-compose up -d
```

### With Optional Services

```bash
# Run core + Zeek forensics
docker-compose --profile zeek up -d

# Run core + timeline builder
docker-compose --profile timeline up -d

# Run core + DoH detection
docker-compose --profile detection up -d

# Run all services (with monitoring)
docker-compose --profile zeek --profile timeline --profile detection --profile monitoring up -d

# View enabled services
docker-compose config --services
```

### Profile Descriptions

| Profile | Services | Purpose | Enabled |
|---------|----------|---------|---------|
| (default) | mod-router | Core DNS + forensics | Yes |
| zeek | zeek | Network packet capture | No |
| timeline | timeline-builder | Hourly device profiles | No |
| detection | doh-detector | DoH/VPN analysis | No |
| monitoring | node-exporter | Prometheus metrics | No |

---

## Configuration

### Environment Variables

```bash
# Core configuration
MOD_ROUTER_HOME=/opt/mod-router
MOD_ROUTER_DB=/opt/mod-router/mod-router.db
MOD_ROUTER_LOGS=/var/log/mod-router
MOD_ROUTER_PCAPS=/var/lib/mod-router/pcaps

# DNS tuning
UNBOUND_THREADS=4              # CPU threads for Unbound
DNSMASQ_CACHE_SIZE=10000       # DNS cache entries
DEBUG=0                         # Enable debug logging
```

### Set Environment Variables

```bash
# In docker-compose.yml
environment:
  MOD_ROUTER_HOME: /opt/mod-router
  UNBOUND_THREADS: "4"

# In docker run command
docker run -e MOD_ROUTER_HOME=/opt/mod-router mod-router:latest

# In .env file (docker-compose)
echo "UNBOUND_THREADS=4" > .env
docker-compose up
```

### Configuration Files

#### Unbound Configuration

Path: `/etc/unbound/conf.d/mod-router.conf`

```nginx
server:
    port: 5353
    access-control: 192.168.0.0/16 allow
    num-threads: 4
    cache-max-ttl: 86400
```

Mount as:

```yaml
volumes:
  - ./config/unbound.conf:/etc/unbound/conf.d/mod-router.conf:ro
```

#### dnsmasq Configuration

Path: `/etc/dnsmasq.d/mod-router.conf`

```bash
port=53
cache-size=10000
log-queries=extra
```

---

## Data Persistence

### Volume Types

#### Named Volumes (Recommended for production)

```yaml
volumes:
  mod-router-db:
    driver: local
```

```bash
# Backup named volume
docker run --rm -v mod-router-db:/data -v $(pwd):/backup \
  busybox tar czf /backup/mod-router-db.tar.gz -C /data .

# Restore named volume
docker run --rm -v mod-router-db:/data -v $(pwd):/backup \
  busybox tar xzf /backup/mod-router-db.tar.gz -C /data
```

#### Bind Mounts (For local development)

```yaml
volumes:
  - ./data/db:/opt/mod-router
  - ./data/logs:/var/log/mod-router
```

### Backup Strategy

```bash
# Backup database only
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db ".backup /tmp/backup.db"
docker cp mod-router:/tmp/backup.db ./backup-$(date +%Y%m%d).db

# Backup logs
docker cp mod-router:/var/log/mod-router ./logs-backup-$(date +%Y%m%d)

# Backup everything
docker run --rm \
  -v mod-router-db:/opt/mod-router \
  -v mod-router-logs:/var/log/mod-router \
  -v $(pwd):/backup \
  busybox tar czf /backup/mod-router-full-$(date +%Y%m%d).tar.gz \
  /opt/mod-router /var/log/mod-router
```

---

## Networking

### Network Modes

#### Bridge Network (Default, Recommended)

```yaml
networks:
  mod-router-network:
    driver: bridge
```

Access:
- From host: `127.0.0.1:53`, `127.0.0.1:5353`
- From other containers: `mod-router:53`, `mod-router:5353`

#### Host Network (For Zeek packet capture)

```yaml
network_mode: host
```

**Warning:** Host network bypasses isolation; use only for Zeek.

#### Custom Network

```bash
# Create network
docker network create mod-router-net

# Run container on network
docker run --network mod-router-net mod-router:latest

# Access from other containers
docker run --network mod-router-net alpine ping mod-router
```

### Port Mapping

| Service | Port | Protocol | Internal Port |
|---------|------|----------|---|
| dnsmasq | 53 | UDP/TCP | 53 |
| Unbound | 5353 | TCP | 5353 |
| Knot | 5354 | UDP | 5354 |
| mitmproxy | 8080 | TCP | 8080 (optional) |

### DNS Upstream Configuration

Forward queries to upstream resolvers:

```bash
# Modify dnsmasq config
server=8.8.8.8#53
server=1.1.1.1#53
server=208.67.222.222#53
```

---

## Security Considerations

### Non-Root User

Dockerfile runs as `mod-router:mod-router` (UID 65534):

```dockerfile
RUN groupadd -r mod-router && useradd -r -g mod-router mod-router
USER mod-router
```

### Capabilities (Minimum Required)

```bash
cap_add:
  - NET_RAW          # Packet capture (Zeek)
  - NET_ADMIN        # Network configuration
  - NET_BIND_SERVICE # Bind to port 53
```

### Security Options

```yaml
security_opt:
  - no-new-privileges:true  # Prevent privilege escalation
```

### Read-Only Filesystem (Optional)

```yaml
read_only: true
tmpfs:
  - /tmp
  - /var/run
```

### Network Isolation

```yaml
networks:
  - mod-router-network

# Restrict external access
environment:
  - ALLOWED_NETWORKS=192.168.0.0/16,10.0.0.0/8
```

### Secret Management (For production)

```bash
# Using Docker secrets
echo "sensitive_data" | docker secret create db_password -

# In compose
secrets:
  db_password:
    external: true

# In service
environment:
  DB_PASSWORD_FILE: /run/secrets/db_password
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs mod-router
docker logs --tail 100 mod-router

# Inspect container
docker inspect mod-router

# Run interactively
docker run -it --rm mod-router:latest bash

# Check image
docker images | grep mod-router
```

### DNS Resolution Fails

```bash
# Test from host
dig @127.0.0.1 -p 53 example.com

# Test from container
docker exec mod-router dig @127.0.0.1 example.com

# Check if services are running
docker exec mod-router systemctl status dnsmasq
docker exec mod-router systemctl status unbound

# Check open ports
docker exec mod-router netstat -tuln | grep LISTEN
```

### Database Errors

```bash
# Check database integrity
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db "SELECT COUNT(*) FROM devices;"

# Repair database
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db "PRAGMA integrity_check;"

# Check database size
docker exec mod-router du -sh /opt/mod-router/mod-router.db
```

### Disk Space Issues

```bash
# Check container disk usage
docker ps -s | grep mod-router

# Check log size
docker exec mod-router du -sh /var/log/mod-router

# Cleanup old logs (in container)
docker exec mod-router find /var/log/mod-router -mtime +30 -delete
```

### Performance Issues

```bash
# Monitor resource usage
docker stats mod-router

# Check query rate
docker exec mod-router tail -f /var/log/mod-router/dnsmasq-queries.log | wc -l

# Increase cache
docker exec mod-router sed -i 's/cache-size=10000/cache-size=50000/' /etc/dnsmasq.d/mod-router.conf
docker restart mod-router
```

---

## Advanced Deployments

### Multi-Container Orchestration

#### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mod-router
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mod-router
  template:
    metadata:
      labels:
        app: mod-router
    spec:
      containers:
      - name: mod-router
        image: mod-router:latest
        securityContext:
          capabilities:
            add:
            - NET_RAW
            - NET_ADMIN
            - NET_BIND_SERVICE
        ports:
        - containerPort: 53
          protocol: UDP
        - containerPort: 5353
          protocol: TCP
        volumeMounts:
        - name: db
          mountPath: /opt/mod-router
        - name: logs
          mountPath: /var/log/mod-router
      volumes:
      - name: db
        persistentVolumeClaim:
          claimName: mod-router-db
      - name: logs
        persistentVolumeClaim:
          claimName: mod-router-logs
```

#### Swarm Deployment

```bash
# Initialize swarm
docker swarm init

# Create service
docker service create \
  --name mod-router \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --cap-add NET_BIND_SERVICE \
  -p 53:53/udp \
  mod-router:latest

# Scale
docker service scale mod-router=3

# Monitor
docker service ps mod-router
```

### High Availability Setup

```yaml
version: '3.9'
services:
  mod-router-1:
    image: mod-router:latest
    environment:
      NODE_ID: "1"
    volumes:
      - /shared/db:/opt/mod-router  # Shared storage
      - /shared/logs:/var/log/mod-router

  mod-router-2:
    image: mod-router:latest
    environment:
      NODE_ID: "2"
    volumes:
      - /shared/db:/opt/mod-router
      - /shared/logs:/var/log/mod-router

  haproxy:
    image: haproxy:2.8
    ports:
      - "53:53/udp"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
```

---

## Performance Tuning

### DNS Performance

```bash
# Increase threads (in environment)
UNBOUND_THREADS=8

# Increase cache size
DNSMASQ_CACHE_SIZE=50000

# Tune kernel
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Reload with changes
docker-compose restart mod-router
```

### Storage Optimization

```bash
# Compress logs
find /var/log/mod-router -type f -name "*.log" -mtime +7 -exec gzip {} \;

# Archive old PCAPs
tar -czf /archive/pcaps-$(date +%Y%m).tar.gz /var/lib/mod-router/pcaps/*.pcap
rm /var/lib/mod-router/pcaps/*.pcap

# Database maintenance
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db "VACUUM; ANALYZE;"
```

### Network Optimization

```bash
# Enable UDP buffer tuning
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728

# Persistent changes in /etc/sysctl.conf
echo "net.core.rmem_max=134217728" >> /etc/sysctl.conf
sysctl -p
```

---

## Monitoring & Logging

### Container Logs

```bash
# Real-time logs
docker-compose logs -f mod-router

# Last 100 lines
docker logs --tail 100 mod-router

# Timestamps
docker logs -t mod-router | tail -50
```

### Database Queries

```bash
# Active queries
docker exec mod-router sqlite3 /opt/mod-router/mod-router.db << 'SQL'
SELECT COUNT(*) as device_count FROM devices;
SELECT COUNT(*) as query_count FROM dns_queries WHERE timestamp > datetime('now', '-1 hour');
SELECT COUNT(*) as incident_count FROM incidents WHERE resolved = 0;
SQL

# Export timeline
docker exec mod-router python3 /opt/mod-router/device-timeline-builder.py > timeline.json
```

### Health Monitoring

```bash
# Healthcheck status
docker inspect mod-router | grep -A 5 Health

# Manual health test
docker exec mod-router /opt/mod-router/healthcheck.sh && echo "OK" || echo "FAIL"
```

---

## Support & Resources

### Documentation
- Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Quick Reference: [QUICKREF.md](QUICKREF.md)
- Audit Report: [DOCKER_AUDIT_REPORT.md](DOCKER_AUDIT_REPORT.md)

### GitHub Issues
- Report bugs: https://github.com/Moddux/mod-router/issues

### Community
- Discussions: https://github.com/Moddux/mod-router/discussions

---

*End of Docker Deployment Guide*

