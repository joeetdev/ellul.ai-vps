/**
 * Doctor script - system diagnostics and health check.
 */
export function getDoctorScript(): string {
  return `#!/bin/bash

GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
RED='\\033[0;31m'
CYAN='\\033[0;36m'
NC='\\033[0m'

echo ""
echo -e "\${CYAN}╔════════════════════════════════════════╗\${NC}"
echo -e "\${CYAN}║     Phone Stack System Diagnostics     ║\${NC}"
echo -e "\${CYAN}╚════════════════════════════════════════╝\${NC}"
echo ""

# 1. Memory Check
echo -e "\${CYAN}[Memory]\${NC}"
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
AVAIL_MEM=$(free -m | awk '/^Mem:/{print $7}')
USED_PCT=$((100 - (AVAIL_MEM * 100 / TOTAL_MEM)))
if [ "$USED_PCT" -gt 90 ]; then
  echo -e "  \${RED}CRITICAL:\${NC} Memory at \${USED_PCT}% (\${AVAIL_MEM}MB free)"
elif [ "$USED_PCT" -gt 70 ]; then
  echo -e "  \${YELLOW}WARNING:\${NC} Memory at \${USED_PCT}% (\${AVAIL_MEM}MB free)"
else
  echo -e "  \${GREEN}OK:\${NC} Memory at \${USED_PCT}% (\${AVAIL_MEM}MB free)"
fi
echo ""

# 2. Disk Check
echo -e "\${CYAN}[Disk]\${NC}"
DISK_PCT=$(df / | awk 'NR==2 {gsub(/%/,""); print $5}')
if [ "$DISK_PCT" -gt 90 ]; then
  echo -e "  \${RED}CRITICAL:\${NC} Disk at \${DISK_PCT}%"
elif [ "$DISK_PCT" -gt 70 ]; then
  echo -e "  \${YELLOW}WARNING:\${NC} Disk at \${DISK_PCT}%"
else
  echo -e "  \${GREEN}OK:\${NC} Disk at \${DISK_PCT}%"
fi
echo ""

# 3. Service Status
echo -e "\${CYAN}[Services]\${NC}"
for SVC in caddy ttyd phonestack-enforcer phonestack-file-api phonestack-preview; do
  if systemctl is-active --quiet $SVC 2>/dev/null; then
    echo -e "  \${GREEN}✓\${NC} $SVC"
  else
    echo -e "  \${RED}✗\${NC} $SVC - attempting restart..."
    sudo systemctl restart $SVC 2>/dev/null
    if systemctl is-active --quiet $SVC 2>/dev/null; then
      echo -e "    \${GREEN}→ Fixed!\${NC}"
    else
      echo -e "    \${RED}→ Failed. Check: journalctl -u $SVC\${NC}"
    fi
  fi
done
echo ""

# 4. PM2 Apps
echo -e "\${CYAN}[PM2 Apps]\${NC}"
if command -v pm2 &>/dev/null; then
  ERRORED=$(pm2 jlist 2>/dev/null | jq -r '.[] | select(.pm2_env.status == "errored") | .name' 2>/dev/null)
  if [ -n "$ERRORED" ]; then
    echo -e "  \${RED}Errored apps:\${NC}"
    for APP in $ERRORED; do
      echo -e "    \${RED}✗\${NC} $APP"
    done
  else
    APP_COUNT=$(pm2 jlist 2>/dev/null | jq '. | length' 2>/dev/null || echo "0")
    echo -e "  \${GREEN}OK:\${NC} $APP_COUNT apps running"
  fi
else
  echo -e "  \${YELLOW}PM2 not found\${NC}"
fi
echo ""

# 5. Caddy Config Test
echo -e "\${CYAN}[Caddy Config]\${NC}"
if caddy validate --config /etc/caddy/Caddyfile 2>/dev/null; then
  echo -e "  \${GREEN}OK:\${NC} Config valid"
else
  echo -e "  \${RED}ERROR:\${NC} Invalid config - run: caddy fmt --overwrite /etc/caddy/Caddyfile"
fi
echo ""

# 6. DNS Check
echo -e "\${CYAN}[DNS]\${NC}"
DOMAIN=$(cat /etc/phonestack/domain 2>/dev/null)
if [ -n "$DOMAIN" ]; then
  if host "$DOMAIN" &>/dev/null; then
    echo -e "  \${GREEN}OK:\${NC} $DOMAIN resolves"
  else
    echo -e "  \${RED}ERROR:\${NC} $DOMAIN does not resolve"
  fi
else
  echo -e "  \${YELLOW}No custom domain configured\${NC}"
fi
echo ""

echo -e "\${CYAN}Done. Run 'phonestack-doctor' anytime to check system health.\${NC}"
echo ""`;
}

/**
 * Performance monitor script - reports status for dashboard.
 *
 * @param apiUrl - The Phone Stack API URL
 * @param aiProxyToken - The server's AI proxy token
 */
export function getPerfMonitorScript(): string {
  return `#!/bin/bash

# Performance monitor for Phone Stack
# - Writes status to JSON file for dashboard to display
# - Reports active listening ports (for "Ghost Process" detection)
# - Never auto-kills anything (observability over automation)

STATUS_FILE="/var/lib/phone-stack/perf-status.json"
mkdir -p /var/lib/phone-stack

# System ports we don't report (not user processes)
# 22=SSH, 80/443=Caddy, 3002=FileAPI, 7681-7690=Terminal
SYSTEM_PORTS="22 80 443 3002 7681 7682 7683 7684 7685 7686 7687 7688 7689 7690"

is_system_port() {
  local port=$1
  for sp in $SYSTEM_PORTS; do
    [ "$port" = "$sp" ] && return 0
  done
  return 1
}

while true; do
  # Get memory stats
  TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
  USED_MEM=$(free -m | awk '/^Mem:/{print $3}')
  AVAIL_MEM=$(free -m | awk '/^Mem:/{print $7}')
  MEM_PCT=$((USED_MEM * 100 / TOTAL_MEM))

  # Get swap stats
  SWAP_USED=$(free -m | awk '/^Swap:/{print $3}')

  # Get load average
  LOAD=$(cat /proc/loadavg | awk '{print $1}')
  LOAD_INT=\${LOAD%.*}

  # Get disk usage
  DISK_PCT=$(df / | awk 'NR==2 {gsub(/%/,""); print $5}')

  # Get active listening ports (user processes only)
  ACTIVE_PORTS=""
  ACTIVE_PORTS_JSON="[]"

  while read -r port; do
    if [ -n "$port" ] && ! is_system_port "$port"; then
      if [ -z "$ACTIVE_PORTS" ]; then
        ACTIVE_PORTS="$port"
        ACTIVE_PORTS_JSON="[$port"
      else
        ACTIVE_PORTS="$ACTIVE_PORTS,$port"
        ACTIVE_PORTS_JSON="$ACTIVE_PORTS_JSON,$port"
      fi
    fi
  done < <(ss -tlnp 2>/dev/null | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -nu)

  [ -n "$ACTIVE_PORTS" ] && ACTIVE_PORTS_JSON="$ACTIVE_PORTS_JSON]" || ACTIVE_PORTS_JSON="[]"

  # Count active user ports
  PORT_COUNT=0
  [ -n "$ACTIVE_PORTS" ] && PORT_COUNT=$(echo "$ACTIVE_PORTS" | tr ',' '\\n' | wc -l)

  # Determine status
  STATUS="good"
  REASON=""

  if [ "$SWAP_USED" -gt 500 ]; then
    STATUS="struggling"
    REASON="High swap usage (\${SWAP_USED}MB)"
  elif [ "$LOAD_INT" -gt 2 ]; then
    STATUS="struggling"
    REASON="High CPU load (\${LOAD})"
  elif [ "$MEM_PCT" -gt 90 ]; then
    STATUS="struggling"
    if [ "$PORT_COUNT" -gt 0 ]; then
      REASON="Low memory (\${AVAIL_MEM}MB free) - \${PORT_COUNT} dev server(s) running"
    else
      REASON="Low memory (\${AVAIL_MEM}MB free)"
    fi
  fi

  # Write status JSON
  cat > "$STATUS_FILE" << JSONEOF
{
  "timestamp": "$(date -Iseconds)",
  "status": "$STATUS",
  "reason": "$REASON",
  "memory": {
    "total": $TOTAL_MEM,
    "used": $USED_MEM,
    "available": $AVAIL_MEM,
    "percent": $MEM_PCT
  },
  "swap": {
    "used": $SWAP_USED
  },
  "load": "$LOAD",
  "disk": {
    "percent": $DISK_PCT
  },
  "activePorts": $ACTIVE_PORTS_JSON,
  "activePortCount": $PORT_COUNT
}
JSONEOF

  # Report to API
  curl -sS -X POST "\${API_URL}/api/servers/heartbeat" \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer \${AI_PROXY_TOKEN}" \\
    -d "{
      \\"cpu\\": $LOAD_INT,
      \\"ram\\": $MEM_PCT,
      \\"status\\": \\"$STATUS\\",
      \\"activePorts\\": $ACTIVE_PORTS_JSON
    }" 2>/dev/null || true

  sleep 60
done`;
}

/**
 * Perf monitor systemd service.
 *
 * @param apiUrl - The Phone Stack API URL
 * @param aiProxyToken - The server's AI proxy token
 */
export function getPerfMonitorService(
  apiUrl: string,
  aiProxyToken: string
): string {
  return `[Unit]
Description=Phone Stack Performance Monitor
After=network.target

[Service]
Type=simple
User=root
Environment=API_URL=${apiUrl}
Environment=AI_PROXY_TOKEN=${aiProxyToken}
ExecStart=/usr/local/bin/phonestack-perf-monitor
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target`;
}
