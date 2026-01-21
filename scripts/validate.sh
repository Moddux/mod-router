#!/bin/bash
# MOD-ROUTER Validation Script
# Comprehensive system health check + forensic capability verification

set -e

ROUTER_HOME="/home/mdx/mod-router"
DATADIR="/opt/mod-router"
LOGDIR="/var/log/mod-router"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           MOD-ROUTER SYSTEM VALIDATION                         ║"
echo "║        Forensic DNS + Network Audit Stack Health Check         ║"
echo "╚════════════════════════════════════════════════════════════════╝"

PASS=0
FAIL=0
WARN=0

# Helper functions
pass() { echo "[✓] $1"; ((PASS++)); }
fail() { echo "[✗] $1"; ((FAIL++)); }
warn() { echo "[!] $1"; ((WARN++)); }

echo ""
echo "=== SYSTEM PREREQUISITES ==="

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VER=$(python3 --version | awk '{print $2}')
    [[ "$PYTHON_VER" > "3.8" ]] && pass "Python 3.9+ installed ($PYTHON_VER)" || warn "Python $PYTHON_VER (recommend 3.9+)"
else
    fail "Python 3 not found"
fi

# Check required tools
for tool in zeek dig nslookup sqlite3 jq tcpdump tshark; do
    command -v $tool &> /dev/null && pass "$tool installed" || warn "$tool not found (optional)"
done

# Check disk space
DISK_FREE=$(df /opt/mod-router 2>/dev/null | tail -1 | awk '{print $4}')
if [ "$DISK_FREE" -gt 1048576 ]; then  # 1GB
    pass "Disk space: ${DISK_FREE}KB available"
else
    warn "Low disk space: ${DISK_FREE}KB"
fi

echo ""
echo "=== DNS AUTHORITY STACK ==="

# Check dnsmasq
if systemctl is-active --quiet dnsmasq 2>/dev/null; then
    pass "dnsmasq running (port 53)"
else
    warn "dnsmasq not running"
fi

# Check Unbound
if systemctl is-active --quiet unbound 2>/dev/null; then
    pass "Unbound running (port 5353)"
else
    warn "Unbound not running"
fi

# Check Knot Resolver
if systemctl is-active --quiet knot-resolver 2>/dev/null; then
    pass "Knot Resolver running (port 5354)"
else
    warn "Knot Resolver not running (optional)"
fi

# Test DNS resolution
if dig @127.0.0.1 -p 53 example.com +short > /dev/null 2>&1; then
    pass "DNS resolution working (localhost:53)"
else
    fail "DNS resolution failed"
fi

# Check query logs
if [ -f "$LOGDIR/dnsmasq-queries.log" ]; then
    QUERY_COUNT=$(wc -l < "$LOGDIR/dnsmasq-queries.log")
    pass "dnsmasq query log: $QUERY_COUNT entries"
else
    warn "dnsmasq query log not found"
fi

if [ -f "$LOGDIR/unbound-queries.log" ]; then
    pass "Unbound query log exists"
else
    warn "Unbound query log not found"
fi

echo ""
echo "=== ZEEK NETWORK FORENSICS ==="

# Check Zeek installation
if command -v zeek &> /dev/null; then
    ZEEK_VER=$(zeek --version 2>&1 | head -1)
    pass "Zeek installed: $ZEEK_VER"
else
    fail "Zeek not installed"
fi

# Check Zeek policies
if [ -d "$ROUTER_HOME/zeek/policies" ]; then
    POLICY_COUNT=$(ls -1 "$ROUTER_HOME/zeek/policies"/*.zeek 2>/dev/null | wc -l)
    pass "Zeek policies: $POLICY_COUNT policies found"
else
    fail "Zeek policy directory not found"
fi

# Check Zeek logs
if [ -d "$LOGDIR/zeek" ]; then
    pass "Zeek log directory exists"
else
    warn "Zeek log directory not created yet"
fi

echo ""
echo "=== DATABASE INFRASTRUCTURE ==="

# Check database
if [ -f "$DATADIR/mod-router.db" ]; then
    pass "Database exists: $DATADIR/mod-router.db"
    
    # Check tables
    TABLES=$(sqlite3 "$DATADIR/mod-router.db" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null)
    [ "$TABLES" -ge 6 ] && pass "Database tables: $TABLES created" || fail "Database tables: $TABLES (expect 6+)"
    
    # Check device records
    DEVICES=$(sqlite3 "$DATADIR/mod-router.db" "SELECT COUNT(*) FROM devices;" 2>/dev/null)
    [ "$DEVICES" -gt 0 ] && pass "Tracked devices: $DEVICES" || warn "No devices tracked yet (expected initially)"
    
    # Check DNS queries
    DNS_QUERIES=$(sqlite3 "$DATADIR/mod-router.db" "SELECT COUNT(*) FROM dns_queries;" 2>/dev/null)
    [ "$DNS_QUERIES" -gt 0 ] && pass "DNS queries logged: $DNS_QUERIES" || warn "No DNS queries logged yet"
    
    # Check flows
    FLOWS=$(sqlite3 "$DATADIR/mod-router.db" "SELECT COUNT(*) FROM flows;" 2>/dev/null)
    [ "$FLOWS" -gt 0 ] && pass "Network flows: $FLOWS" || warn "No flows logged yet"
    
else
    fail "Database not initialized"
fi

echo ""
echo "=== FORENSIC TOOLS ==="

# Check device timeline builder
if [ -f "$DATADIR/device-timeline-builder.py" ]; then
    pass "Device timeline builder installed"
else
    fail "Device timeline builder missing"
fi

# Check ASN enrichment
if [ -f "$DATADIR/asn-enrichment.py" ]; then
    pass "ASN enrichment tool installed"
else
    fail "ASN enrichment tool missing"
fi

# Check incident reporter
if [ -f "$DATADIR/incident-report.py" ]; then
    pass "Incident report tool installed"
else
    fail "Incident report tool missing"
fi

# Check PCAP exporter
if [ -f "$DATADIR/pcap-exporter.sh" ]; then
    pass "PCAP exporter installed"
else
    fail "PCAP exporter missing"
fi

echo ""
echo "=== DOH/VPN DETECTION ==="

# Check DoH analyzer
if [ -f "$DATADIR/doh-analyzer.py" ]; then
    pass "DoH analyzer installed"
else
    fail "DoH analyzer missing"
fi

# Check DoH blocklist
if [ -f "$DATADIR/doh-blocklist.txt" ]; then
    BLOCK_COUNT=$(wc -l < "$DATADIR/doh-blocklist.txt")
    pass "DoH blocklist: $BLOCK_COUNT entries"
else
    warn "DoH blocklist not found"
fi

# Check nftables
if command -v nft &> /dev/null; then
    pass "nftables installed (for DoH blocking)"
else
    warn "nftables not installed (fallback to iptables)"
fi

echo ""
echo "=== MITM LAB MODE (OPTIONAL) ==="

# Check MITM lab directory
if [ -d "/opt/mod-router/mitm-lab" ]; then
    pass "MITM lab directory exists"
    
    # Check CA certificate
    if [ -f "/opt/mod-router/mitm-lab/certs/mod-router-ca.pem" ]; then
        pass "Root CA certificate generated"
    else
        warn "Root CA not generated"
    fi
    
    # Check mitmproxy config
    if [ -f "/opt/mod-router/mitm-lab/mitmproxy-config.py" ]; then
        pass "mitmproxy addon configured"
    else
        warn "mitmproxy config missing"
    fi
else
    warn "MITM lab not initialized"
fi

echo ""
echo "=== CRON JOBS ==="

# Check cron jobs
if crontab -l 2>/dev/null | grep -q "mod-router"; then
    CRON_COUNT=$(crontab -l 2>/dev/null | grep -c "mod-router")
    pass "Cron jobs configured: $CRON_COUNT jobs"
else
    warn "No cron jobs found (optional)"
fi

echo ""
echo "=== LOG DIRECTORIES ==="

# Check log directories
if [ -d "$LOGDIR" ]; then
    LOGSIZE=$(du -sh "$LOGDIR" 2>/dev/null | awk '{print $1}')
    pass "Log directory: $LOGDIR ($LOGSIZE)"
else
    fail "Log directory not created"
fi

# Check pcap directory
if [ -d "/var/lib/mod-router/pcaps" ]; then
    PCAPSIZE=$(du -sh "/var/lib/mod-router/pcaps" 2>/dev/null | awk '{print $1}')
    pass "PCAP directory: $PCAPSIZE"
else
    warn "PCAP directory not created (expected during runtime)"
fi

echo ""
echo "=== PYTHON DEPENDENCIES ==="

# Check Python modules
python3 << 'EOFPYTHON'
import sys

modules = ['sqlite3', 'json', 'requests', 'arrow']
missing = []

for module in modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)

if not missing:
    print("[✓] All required Python modules installed")
else:
    print(f"[!] Missing Python modules: {', '.join(missing)}")
    sys.exit(1)
EOFPYTHON

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    VALIDATION RESULTS                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"

echo ""
echo "✓ PASS: $PASS"
echo "! WARN: $WARN"
echo "✗ FAIL: $FAIL"

if [ $FAIL -eq 0 ]; then
    echo ""
    echo "[✓] MOD-ROUTER is ready for deployment!"
    echo ""
    echo "Next steps:"
    echo "  1. Verify all DNS services are running"
    echo "  2. Configure network interface (Zeek): sudo $ROUTER_HOME/scripts/zeek-runner.sh eth0"
    echo "  3. Monitor logs: tail -f $LOGDIR/dnsmasq-queries.log"
    echo "  4. Test forensics: python3 $DATADIR/device-timeline-builder.py"
    echo "  5. Review QUICKREF.md for operational commands"
    exit 0
else
    echo ""
    echo "[✗] MOD-ROUTER has $FAIL critical issues. Review above and remediate."
    exit 1
fi
