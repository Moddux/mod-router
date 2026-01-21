#!/bin/bash
# Pi-hole + Unbound + Knot Resolver DNS authority deployment
# Enables: comprehensive DNS query logging, DoH blocking, device tracking

set -e

ROUTER_HOME="/home/mdx/mod-router"
DATADIR="/opt/mod-router"
LOGDIR="/var/log/mod-router"

echo "[*] Deploying DNS authority stack..."

# === UNBOUND RECURSIVE RESOLVER ===
echo "[+] Configuring Unbound..."

sudo tee /etc/unbound/conf.d/mod-router.conf > /dev/null << 'EOF'
# Unbound configuration for MOD-ROUTER
# Recursive resolver with DNSSEC validation + full query logging

server:
    interface: 0.0.0.0
    interface: ::0
    port: 5353
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 127.0.0.0/8 allow
    
    # DNSSEC validation
    auto-trust-anchor: yes
    trust-anchor: "root DNSKEY 257 3 8 AwEAAaetidLzsN2DP3BDBRt7yVrLji7Ud+AUApyxBVJ455FH7l8G8rOVM36MY5dnSa8M9/Xl8h9xXHVZ7PgIjnWaZV5dcWqD"
    
    # Query logging
    log-queries: yes
    log-replies: yes
    logfile: "/var/log/mod-router/unbound-queries.log"
    log-time-ascii: yes
    
    # Performance
    num-threads: 4
    outgoing-num-tcp: 10
    outgoing-port-avoid: "0-32767"
    
    # Caching
    cache-max-ttl: 86400
    cache-min-ttl: 300

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-interface: ::1
    control-use-cert: no
EOF

sudo systemctl enable unbound
sudo systemctl restart unbound
echo "[+] Unbound running on port 5353"

# === DNSMASQ + PIHOLE-STYLE BLOCKING ===
echo "[+] Configuring DNS blocking (Pi-hole equivalent)..."

cat > "$DATADIR/adlists.txt" << 'EOF'
# Pi-hole blocklists + DoH blocklist
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://mirror1.malwaredomains.com/files/justdomains
https://raw.githubusercontent.com/phishing-army/phishing-army-rules/master/phishing-army-rules.txt
https://api.github.com/repos/easylist/easylist/contents/easylist.txt
https://easylist-downloads.adblockplus.org/easyprivacy.txt
# DoH endpoints (to block)
https://raw.githubusercontent.com/curl/curl/master/docs/DoH.md
EOF

cat > "$DATADIR/build-dnsmasq-blocklist.sh" << 'EOFSCRIPT'
#!/bin/bash
# Build dnsmasq-compatible blocklist from adlists

BLOCKLIST_FILE="/etc/dnsmasq.d/mod-router-blocklist.conf"
ADLIST_FILE="/opt/mod-router/adlists.txt"
TEMP_HOSTS="/tmp/hosts-combined.txt"

echo "[*] Building blocklist from adlists..."
> "$TEMP_HOSTS"

while IFS= read -r url; do
    [[ "$url" =~ ^#.* ]] && continue
    [[ -z "$url" ]] && continue
    echo "[*] Fetching: $url"
    curl -s "$url" >> "$TEMP_HOSTS" 2>/dev/null || true
done < "$ADLIST_FILE"

# Convert hosts format to dnsmasq conf
awk 'NF && !/^#/ {
    if ($1 ~ /^[0-9.]+$/) {
        # hosts format: IP domain
        for (i=2; i<=NF; i++) {
            print "address=/" $i "/0.0.0.0"
        }
    } else {
        # domain-only format
        print "address=/" $1 "/0.0.0.0"
    }
}' "$TEMP_HOSTS" | sort -u > "$BLOCKLIST_FILE"

wc -l "$BLOCKLIST_FILE"
echo "[+] Blocklist built: $(grep -c 'address=' $BLOCKLIST_FILE) domains"
EOFSCRIPT

chmod +x "$DATADIR/build-dnsmasq-blocklist.sh"

sudo tee /etc/dnsmasq.d/mod-router.conf > /dev/null << 'EOF'
# dnsmasq configuration for MOD-ROUTER
# Primary DNS with blocking, DHCP logging

# Interface binding
interface=*
bind-interfaces
port=53

# Upstream DNS (Unbound + public fallback)
server=127.0.0.1#5353
server=1.1.1.1#53
server=8.8.8.8#53

# DHCP server (for device tracking)
dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
dhcp-leasefile=/var/lib/dnsmasq/dhcp.leases

# Query logging
log-queries=extra
log-facility=/var/log/mod-router/dnsmasq-queries.log

# Cache settings
cache-size=10000
neg-ttl=3600

# Block DoH endpoints
address=/dns.google/0.0.0.0
address=/1.1.1.1/0.0.0.0
address=/dns.cloudflare.com/0.0.0.0
address=/dns.apple.com/0.0.0.0
address=/dns.quad9.net/0.0.0.0

# Load compiled blocklist
conf-dir=/etc/dnsmasq.d/,*.conf
EOF

sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq
echo "[+] dnsmasq (Pi-hole equivalent) configured on port 53"

# === KNOT RESOLVER (FALLBACK/CACHE) ===
echo "[+] Configuring Knot Resolver..."

sudo tee /etc/knot-resolver/kresd.conf > /dev/null << 'EOF'
-- Knot Resolver configuration for MOD-ROUTER
-- Fallback resolver with caching

modules = { 'hints', 'stats', 'predict' }
cache.size = 100 * MB

-- Listen on all interfaces
net.listen('0.0.0.0', 5354, { kind = 'dns' })
net.listen('::', 5354, { kind = 'dns' })

-- Upstream servers
upstream.add('127.0.0.1:5353')     -- Unbound
upstream.add('1.1.1.1')             -- Cloudflare fallback
upstream.add('8.8.8.8')             -- Google fallback

-- Query statistics
stats.enable(true)

-- Return 0.0.0.0 for blocked domains
policy.add(policy.suffix(policy.DENY, {todname('dns.google')}))
policy.add(policy.suffix(policy.DENY, {todname('dns.cloudflare.com')}))
EOF

sudo systemctl enable knot-resolver
sudo systemctl restart knot-resolver
echo "[+] Knot Resolver configured on port 5354"

# === DHCP LEASE PARSING ===
cat > "$DATADIR/parse-dhcp-leases.py" << 'EOFPYTHON'
#!/usr/bin/env python3
# Parse dnsmasq DHCP leases and populate device database

import sqlite3
import sys
from datetime import datetime

DB_PATH = "/opt/mod-router/mod-router.db"
LEASES_FILE = "/var/lib/dnsmasq/dhcp.leases"

def parse_dhcp_leases():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        with open(LEASES_FILE, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                
                lease_end, mac, ipv4, hostname, _ = parts[0], parts[1], parts[2], parts[3], parts[4] if len(parts) > 4 else ""
                
                # Check if device exists
                cursor.execute("SELECT device_id FROM devices WHERE mac_addr = ?", (mac,))
                result = cursor.fetchone()
                
                if result:
                    # Update existing
                    cursor.execute("""
                        UPDATE devices 
                        SET ipv4_addr = ?, hostname = ?, dhcp_lease_end = ?, last_seen = CURRENT_TIMESTAMP 
                        WHERE mac_addr = ?
                    """, (ipv4, hostname, datetime.utcfromtimestamp(int(lease_end)), mac))
                else:
                    # Insert new
                    device_id = mac.replace(':', '_')
                    cursor.execute("""
                        INSERT INTO devices (device_id, mac_addr, ipv4_addr, hostname, dhcp_lease_end)
                        VALUES (?, ?, ?, ?, ?)
                    """, (device_id, mac, ipv4, hostname, datetime.utcfromtimestamp(int(lease_end))))
        
        conn.commit()
        print(f"[+] DHCP leases synced: {cursor.rowcount} devices updated")
    except Exception as e:
        print(f"[-] Error parsing DHCP leases: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    parse_dhcp_leases()
EOFPYTHON

chmod +x "$DATADIR/parse-dhcp-leases.py"

# === DNS QUERY LOG PARSER ===
cat > "$DATADIR/parse-dns-logs.py" << 'EOFPYTHON'
#!/usr/bin/env python3
# Parse dnsmasq + Unbound query logs, enrich with device info

import sqlite3
import re
from datetime import datetime
from pathlib import Path

DB_PATH = "/opt/mod-router/mod-router.db"
DNSMASQ_LOG = "/var/log/mod-router/dnsmasq-queries.log"
UNBOUND_LOG = "/var/log/mod-router/unbound-queries.log"

def parse_dnsmasq_logs():
    """Parse dnsmasq query logs"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if not Path(DNSMASQ_LOG).exists():
        print(f"[-] Log not found: {DNSMASQ_LOG}")
        return
    
    # dnsmasq format: Aug 15 12:34:56 dnsmasq[1234]: query[A] example.com from 192.168.1.100
    pattern = r'query\[(\w+)\] (\S+) from ([\d.]+)'
    
    try:
        with open(DNSMASQ_LOG, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    qtype, domain, src_ip = match.groups()
                    
                    # Get device MAC from IP
                    cursor.execute("SELECT device_id, mac_addr FROM devices WHERE ipv4_addr = ?", (src_ip,))
                    device = cursor.fetchone()
                    device_id = device[0] if device else f"unknown_{src_ip}"
                    mac_addr = device[1] if device else "unknown"
                    
                    # Insert query log
                    cursor.execute("""
                        INSERT INTO dns_queries (device_id, client_ip, client_mac, queried_domain, query_type, resolver_used)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (device_id, src_ip, mac_addr, domain, qtype, "dnsmasq"))
        
        conn.commit()
        print(f"[+] Parsed dnsmasq queries: {cursor.rowcount} entries")
    except Exception as e:
        print(f"[-] Error parsing dnsmasq logs: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    parse_dnsmasq_logs()
EOFPYTHON

chmod +x "$DATADIR/parse-dns-logs.py"

# === CRON JOB FOR CONTINUOUS SYNC ===
cat > "$DATADIR/cron-sync-dns.sh" << 'EOFCRON'
#!/bin/bash
# Cron job: sync DHCP leases and DNS queries every 5 minutes

DATADIR="/opt/mod-router"

python3 "$DATADIR/parse-dhcp-leases.py"
python3 "$DATADIR/parse-dns-logs.py"
EOFCRON

chmod +x "$DATADIR/cron-sync-dns.sh"

(crontab -l 2>/dev/null; echo "*/5 * * * * $DATADIR/cron-sync-dns.sh") | crontab -

echo "[+] DNS authority stack deployed!"
echo "[+] Services running:"
echo "    - Unbound (port 5353): Recursive resolver"
echo "    - dnsmasq (port 53): Primary DNS + blocking"
echo "    - Knot Resolver (port 5354): Fallback cache"
echo "[+] Query logs: $LOGDIR/"
