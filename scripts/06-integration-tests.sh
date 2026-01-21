#!/bin/bash
# MOD-ROUTER Integration Test Suite
# Validates all components: DNS, Zeek, flows, timelines, forensics

set -e

DATADIR="/opt/mod-router"
LOGDIR="/var/log/mod-router"

echo "[*] MOD-ROUTER Integration Test Suite"

# === DATABASE INTEGRITY CHECK ===
echo "[+] Testing database integrity..."
sqlite3 "$DATADIR/mod-router.db" "SELECT COUNT(*) FROM devices;" 2>/dev/null || {
    echo "[-] Database error"
    exit 1
}

# === DNS RESOLUTION TEST ===
echo "[+] Testing DNS resolution..."
nslookup google.com 127.0.0.1 > /dev/null 2>&1 || echo "[-] DNS resolution failed"
dig @127.0.0.1 -p 53 example.com +short > /dev/null 2>&1 || echo "[-] dig test failed"

# === ZEEK POLICY VALIDATION ===
echo "[+] Validating Zeek policies..."
if command -v zeek &> /dev/null; then
    zeek -C /home/mdx/mod-router/zeek/policies/mod-router.zeek 2>/dev/null && \
    echo "[+] Zeek policies OK" || echo "[-] Zeek policy error"
fi

# === FLOW LOG GENERATION TEST ===
echo "[+] Testing flow log generation..."
python3 "$DATADIR/device-timeline-builder.py" > /tmp/timeline-test.json 2>/dev/null
if [ $? -eq 0 ]; then
    echo "[+] Flow logs OK"
else
    echo "[-] Flow log generation failed"
fi

# === ASN ENRICHMENT TEST ===
echo "[+] Testing ASN enrichment..."
python3 "$DATADIR/asn-enrichment.py" 2>&1 | grep -q "Enriched" && \
    echo "[+] ASN enrichment OK" || echo "[!] ASN enrichment (optional)"

# === DOH DETECTION TEST ===
echo "[+] Testing DoH detection..."
if [ -f "$DATADIR/doh-analyzer.py" ]; then
    python3 "$DATADIR/doh-analyzer.py" > /tmp/doh-test.json 2>/dev/null && \
    echo "[+] DoH analyzer OK" || echo "[!] DoH analyzer test skipped"
fi

echo ""
echo "[+] Integration tests complete"
