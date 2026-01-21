#!/bin/bash
# Complete MOD-ROUTER deployment orchestrator
# One-command deployment of all components

set -e

ROUTER_HOME="/home/mdx/mod-router"
SCRIPTS="$ROUTER_HOME/scripts"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║    MOD-ROUTER: Forensic DNS + Network Audit Stack             ║"
echo "║    Deploying complete infrastructure...                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Make all scripts executable
chmod +x "$SCRIPTS"/*.sh

# === PHASE 1: System Setup ===
echo ""
echo "[PHASE 1] System initialization and dependencies..."
bash "$SCRIPTS/00-deploy-stack.sh" || {
    echo "[-] Phase 1 failed"
    exit 1
}

# === PHASE 2: Zeek Configuration ===
echo ""
echo "[PHASE 2] Zeek network forensics configuration..."
bash "$SCRIPTS/01-zeek-config.sh" || echo "[!] Phase 2 partial failure"

# === PHASE 3: DNS Authority ===
echo ""
echo "[PHASE 3] DNS authority stack (Pi-hole + Unbound + Knot)..."
bash "$SCRIPTS/02-dns-authority.sh" || echo "[!] Phase 3 partial failure"

# === PHASE 4: Device Timeline ===
echo ""
echo "[PHASE 4] Device behavioral timeline system..."
bash "$SCRIPTS/03-device-timeline.sh" || echo "[!] Phase 4 partial failure"

# === PHASE 5: DoH Detection ===
echo ""
echo "[PHASE 5] DoH/VPN detection and blocking..."
bash "$SCRIPTS/04-doh-detection.sh" || echo "[!] Phase 5 partial failure"

# === PHASE 6: MITM Lab (Optional) ===
echo ""
echo "[PHASE 6] MITM lab mode (authorized testing only)..."
bash "$SCRIPTS/05-mitm-lab-setup.sh" || echo "[!] Phase 6 partial failure"

# === PHASE 7: Integration Tests ===
echo ""
echo "[PHASE 7] Integration and validation tests..."
bash "$SCRIPTS/06-integration-tests.sh" || echo "[!] Phase 7 partial failure"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                DEPLOYMENT COMPLETE                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# === FINAL STATUS ===
echo ""
echo "[*] Running services:"
systemctl is-active unbound 2>/dev/null && echo "  [✓] Unbound (port 5353)" || echo "  [ ] Unbound"
systemctl is-active dnsmasq 2>/dev/null && echo "  [✓] dnsmasq (port 53)" || echo "  [ ] dnsmasq"
systemctl is-active knot-resolver 2>/dev/null && echo "  [✓] Knot Resolver (port 5354)" || echo "  [ ] Knot Resolver"

echo ""
echo "[*] Next steps:"
echo "    1. Start Zeek: sudo $SCRIPTS/zeek-runner.sh eth0"
echo "    2. Verify DNS: dig @127.0.0.1 example.com"
echo "    3. Check logs: ls -la /var/log/mod-router/"
echo "    4. Build timelines: python3 /opt/mod-router/device-timeline-builder.py"
echo "    5. Detect DoH: python3 /opt/mod-router/doh-analyzer.py"
echo ""
echo "[*] Documentation:"
echo "    - Repo: $ROUTER_HOME"
echo "    - README: $ROUTER_HOME/README.md"
echo "    - Logs: /var/log/mod-router/"
echo "    - Database: /opt/mod-router/mod-router.db"
