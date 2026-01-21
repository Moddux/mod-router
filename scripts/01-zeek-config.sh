#!/bin/bash
# Zeek configuration and policy deployment
# Enables: DNS logging, TLS metadata, DoH detection, flow analysis

set -e

ROUTER_HOME="/home/mdx/mod-router"
ZEEK_POLICY_DIR="/opt/zeek/share/zeek/site"
DATADIR="/opt/mod-router"

echo "[*] Configuring Zeek for MOD-ROUTER forensics..."

# === ZEEK LOCAL NETWORK CONFIG ===
mkdir -p "$ROUTER_HOME/zeek/policies"

cat > "$ROUTER_HOME/zeek/policies/mod-router.zeek" << 'EOF'
# MOD-ROUTER Forensic Zeek Policies
# Logs: DNS queries, TLS metadata (JA3/SNI), QUIC, flows, file hashes

@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/http
@load base/protocols/quic
@load base/frameworks/notice
@load base/frameworks/sumstats

# Custom logging fields
module MOD_ROUTER;

export {
    redef enum Notice::Type += {
        MOD_ROUTER::DoH_Detected,
        MOD_ROUTER::DNS_Blocked,
        MOD_ROUTER::Suspicious_TLS,
        MOD_ROUTER::Unknown_Device,
    };
}

# === DNS FORENSICS ===
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( qtype == DNS_A || qtype == DNS_AAAA || qtype == DNS_MX || qtype == DNS_CNAME ) {
        print fmt("[DNS_QUERY] %s -> %s (type=%s) [%s]", 
            c$id$orig_h, query, DNS_type_to_str(qtype), strftime("%Y-%m-%d %H:%M:%S", network_time()));
    }
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    print fmt("[DNS_REPLY] %s resolved to %s [%s]", 
        ans$query, a, strftime("%Y-%m-%d %H:%M:%S", network_time()));
}

# === TLS/SSL METADATA ===
event ssl_client_hello(c: connection, version: count, possible_ts: count, client_random: string, 
        session_id: string, ciphers: index_vec) {
    print fmt("[TLS_CLIENT_HELLO] %s -> %s (version=0x%04x) [%s]", 
        c$id$orig_h, c$id$resp_h, version, strftime("%Y-%m-%d %H:%M:%S", network_time()));
}

event ssl_server_certificate(c: connection, cert: X509, err: string) {
    if ( cert$subject?$CN ) {
        print fmt("[TLS_CERT] CN=%s issuer=%s [%s]", 
            cert$subject$CN, cert$issuer$CN, strftime("%Y-%m-%d %H:%M:%S", network_time()));
    }
}

# === QUIC DETECTION ===
event quic_client_initial(c: connection, version: count, supported_versions: vector of count) {
    print fmt("[QUIC] %s -> %s (version=0x%08x) [%s]", 
        c$id$orig_h, c$id$resp_h, version, strftime("%Y-%m-%d %H:%M:%S", network_time()));
}

# === DoH DETECTION ===
event http_request(c: connection, method: string, uri: string, version: string, headers: http_header_table) {
    if ( /dns-query/ in uri || /dns-pad/ in uri ) {
        NOTICE([$note=MOD_ROUTER::DoH_Detected, 
                $conn=c, 
                $msg=fmt("DoH detected: %s %s", method, uri)]);
        print fmt("[DoH_DETECTED] %s -> %s (URI=%s) [%s]", 
            c$id$orig_h, c$id$resp_h, uri, strftime("%Y-%m-%d %H:%M:%S", network_time()));
    }
}

# === FLOW JSON OUTPUT ===
event Zeek::log_init(writers: set[Log::Writer]) {
    Log::default_ext_func = Log::log_ext_with_all_fields;
}
EOF

cat > "$ROUTER_HOME/zeek/policies/custom-logging.zeek" << 'EOF'
# Custom JSON logging for forensic retention

module MOD_ROUTER;

export {
    global mod_router_dns_log = open_log_file("dns-forensics");
    global mod_router_tls_log = open_log_file("tls-metadata");
    global mod_router_quic_log = open_log_file("quic-flows");
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local ts = strftime("%Y-%m-%d %H:%M:%S.%f", network_time());
    local entry = fmt("{\"timestamp\":\"%s\",\"src_ip\":\"%s\",\"query\":\"%s\",\"type\":\"%s\"}", 
        ts, c$id$orig_h, query, DNS_type_to_str(qtype));
    print mod_router_dns_log, entry;
}
EOF

echo "[+] Zeek policies created in $ROUTER_HOME/zeek/policies/"

# === ZEEK RUNTIME CONFIG ===
cat > "$ROUTER_HOME/zeek/node.cfg" << 'EOF'
# Zeek node configuration for MOD-ROUTER
[zeek]
type=standalone
host=localhost
interface=eth0

[logger]
type=logger
host=localhost
EOF

cat > "$ROUTER_HOME/zeek/zeekctl.cfg" << 'EOF'
# zeekctl configuration
LogDir=/var/log/zeek
SpoolDir=/var/spool/zeek
StatsDays=0
UseSQLiteLogging=1
EOF

# === ZEEK RUNTIME SCRIPT ===
cat > "$ROUTER_HOME/scripts/zeek-runner.sh" << 'EOFSCRIPT'
#!/bin/bash
# Run Zeek with MOD-ROUTER policies

INTERFACE="${1:-eth0}"
POLICY_DIR="/home/mdx/mod-router/zeek/policies"
OUTPUT_DIR="/var/log/mod-router/zeek"
PCAP_DIR="/var/lib/mod-router/pcaps"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Zeek on $INTERFACE with MOD-ROUTER policies..."

# Live packet capture + policy analysis
sudo zeek -i "$INTERFACE" \
    -C \
    -L "$POLICY_DIR/mod-router.zeek" \
    -L "$POLICY_DIR/custom-logging.zeek" \
    --logdir "$OUTPUT_DIR"

echo "[+] Zeek running. Logs: $OUTPUT_DIR"
EOFSCRIPT

chmod +x "$ROUTER_HOME/scripts/zeek-runner.sh"

echo "[+] Zeek configuration complete!"
echo "[+] To start Zeek: ./scripts/zeek-runner.sh eth0"
