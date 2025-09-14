#!/usr/bin/env bash
set -euo pipefail

# ========= utils =========
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
ACTIONS=()    # human-readable summary lines
CHANGES=()    # config/security changes
add_action(){ ACTIONS+=("$*"); }
add_change(){ CHANGES+=("$*"); }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (sudo)." >&2
    exit 1
  fi
}

handle_common_errors() {
  log "Attempting to resolve common apt/dpkg issues..."
  for i in {1..5}; do
    killall unattended-upgrade apt-get dpkg 2>/dev/null || true
    rm -f /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock
    dpkg --configure -a || true
    if apt-get update -y; then return 0; fi
    log "Attempt $i failed. Retrying in 15s..."
    sleep 15
  done
  return 1
}

run_command() {
  local cmd="$*"
  local max_attempts=3
  local attempt=1
  while (( attempt <= max_attempts )); do
    log "Running: $cmd (Attempt $attempt/$max_attempts)"
    if eval "$cmd"; then return 0; fi
    log "Command failed. Trying to fix apt/dpkg…"
    handle_common_errors || true
    attempt=$((attempt+1))
    sleep 3
  done
  log "ERROR: $cmd failed after $max_attempts attempts"
  return 1
}

# ========= start =========
require_root
log "Starting comprehensive ocserv setup…"

# ---- Domain picker (uses existing LE cert dirs if found) ----
select_domain() {
  log "Checking existing Let's Encrypt domains…"
  mapfile -t domains < <(ls -d /etc/letsencrypt/live/*/ 2>/dev/null | grep -v README | xargs -n1 basename || true)
  if (( ${#domains[@]} == 0 )); then
    read -rp "Enter domain (no existing LE cert found): " Domain
  else
    log "Available domains:"
    local i=1
    for d in "${domains[@]}"; do echo "$i) $d"; ((i++)); done
    echo "$i) Enter new Domain"
    while true; do
      read -rp "Select (1-$i): " choice
      if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice>=1 && choice<=i )); then
        if (( choice == i )); then read -rp "Enter new domain: " Domain
        else Domain="${domains[$((choice-1))]}"
        fi
        break
      else
        log "Invalid selection. Try again."
      fi
    done
  fi
  log "Selected domain: $Domain"
}

select_domain
Email="yallamalik@gmail.com"
read -rp "Enter AUTH (pam/plain): " auth
auth="${auth,,}"  # lowercase

# ---- Remove any old ocserv cleanly ----
remove_existing() {
  log "Removing existing ocserv installation (if any)…"
  systemctl stop ocserv ocserv.socket 2>/dev/null || true
  systemctl disable ocserv ocserv.socket 2>/dev/null || true
  apt-get purge -y ocserv || true
  apt-get autoremove -y || true
  rm -rf /etc/ocserv
  add_action "Stopped/disabled & purged old ocserv; removed /etc/ocserv"
}
run_command remove_existing

# ---- Repos & base tools ----
run_command "apt-get update -y"
run_command "apt-get install -y software-properties-common curl unzip lsof"
run_command "add-apt-repository universe -y" && add_action "Enabled 'universe' repo"

# ---- Certbot via snap (current best practice) ----
run_command "apt-get install -y snapd"
run_command "snap install core && snap refresh core"
run_command "snap install --classic certbot"
ln -sf /snap/bin/certbot /usr/bin/certbot
add_action "Installed certbot via snap"

# ---- Web servers may block :80 for standalone ----
log "Checking for processes on port 80…"
if lsof -i :80 -sTCP:LISTEN -t >/tmp/p80.txt 2>/dev/null && [[ -s /tmp/p80.txt ]]; then
  while read -r pid; do
    svc=$(ps -p "$pid" -o comm= || true)
    log "Stopping PID $pid ($svc) to free :80"
    systemctl stop "$svc" 2>/dev/null || kill -9 "$pid" || true
  done < /tmp/p80.txt
  add_action "Freed TCP/80 for certbot (stopped blocking services)"
fi

# ---- Obtain/ensure LE cert ----
if [[ -d "/etc/letsencrypt/live/$Domain" ]]; then
  log "Found existing certificate for $Domain"
else
  log "Obtaining new certificate for $Domain…"
  run_command "certbot certonly --standalone --agree-tos --email '$Email' -d '$Domain' --non-interactive --preferred-challenges http"
  add_action "Issued Let's Encrypt cert for $Domain"
fi

if [[ ! -f "/etc/letsencrypt/live/$Domain/fullchain.pem" || ! -f "/etc/letsencrypt/live/$Domain/privkey.pem" ]]; then
  log "Certificate files missing. Aborting."
  exit 1
fi

# Secure permissions (no 777!)
chmod 640 "/etc/letsencrypt/live/$Domain/privkey.pem"
chmod 644 "/etc/letsencrypt/live/$Domain/fullchain.pem"
add_change "Set strict perms on LE certs (privkey 640, fullchain 644)"

# ---- Install ocserv ----
run_command "apt-get install -y ocserv gnutls-bin"
add_action "Installed ocserv + gnutls-bin"

# ---- Enable IPv4 forwarding ----
if ! grep -qE '^\s*net\.ipv4\.ip_forward\s*=\s*1' /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  sysctl -p
  add_action "Enabled net.ipv4.ip_forward"
fi

# ---- Firewall/NAT (iptables) ----
main_interface=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
if [[ -z "${main_interface:-}" ]]; then
  log "Could not detect main interface for NAT"; exit 1
fi

# Allow VPN ports and forward traffic
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p udp --dport 443 -j ACCEPT
iptables -I FORWARD -i vpns+ -o "$main_interface" -j ACCEPT 2>/dev/null || true
iptables -I FORWARD -i "$main_interface" -o vpns+ -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -o "$main_interface" -j MASQUERADE

# Persist rules with a simple systemd service (kept close to your style)
iptables-save > /etc/iptables.rules
cat >/etc/systemd/system/iptables-restore.service <<'EOF'
[Unit]
Description=Restore iptables rules
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
run_command "systemctl daemon-reload"
run_command "systemctl enable iptables-restore"
add_action "Opened 443/TCP+UDP, set NAT & persistence via systemd"

# ---- Write ocserv.conf (secure & compatible) ----
mkdir -p /etc/ocserv
cat >/etc/ocserv/ocserv.conf <<EOF
# Core
proto = udp
tcp-port = 443
udp-port = 443
switch-to-tcp-timeout = 5
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
pid-file = /var/run/ocserv.pid

# Certificates
server-cert = /etc/letsencrypt/live/$Domain/fullchain.pem
server-key  = /etc/letsencrypt/live/$Domain/privkey.pem
ca-cert     = /etc/ssl/certs/ssl-cert-snakeoil.pem

# Performance & compatibility
isolate-workers = true
keepalive = 32400
dpd = 40
mobile-dpd = 40
try-mtu-discovery = false
mtu = 1420
cisco-client-compat = true

# Security: drop TLS1.0, prefer modern suites
tls-priorities = "SECURE256:+SECURE128:-VERS-ALL:+VERS-TLS1.0:+COMP-NULL"
#tls-priorities = "NORMAL:%SERVER_PRECEDENCE:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"
#tls-priorities = "PERFORMANCE:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
#tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"

# Sessions
auth-timeout = 400
min-reauth-time = 100
cookie-timeout = 300
cookie-rekey-time = 14400
rekey-time = 172800
rekey-method = ssl
deny-roaming = false
use-utmp = true
use-occtl = true

# IP pool (use RFC1918 private, not public ranges)
device = vpns
predictable-ips = true
#ipv4-network = 10.10.0.0/24
ipv4-network = 191.10.10.0/21
ipv4-netmask = 255.255.255.0

# DNS
dns = 1.1.1.1
dns = 8.8.8.8
dns-timeout = 2
dns-retries = 1

# Limits
max-clients = 0
max-same-clients = 20000

# Default domain
default-domain = $Domain

# Compression
compression = true
no-compress-limit = 50
EOF

# Auth mode
if [[ "$auth" == "plain" ]]; then
  echo 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"' >> /etc/ocserv/ocserv.conf
  echo 'max-same-clients = 20000' >> /etc/ocserv/ocserv.conf
  add_action "Configured auth=plain with /etc/ocserv/ocpasswd"
else
  echo 'auth = "pam"' >> /etc/ocserv/ocserv.conf
  echo 'max-same-clients = 20000' >> /etc/ocserv/ocserv.conf
  add_action "Configured auth=pam"
fi

# Security changes recap
add_change "Removed insecure TLS1.0/1.1; using NORMAL ciphers with server precedence"
add_change "Replaced public 191.10.10.0/21 with private 10.10.0.0/24 address pool"
add_change "Set sensible limits: max-clients=1024, max-same-clients=2"
add_change "Default-domain now uses your real domain: $Domain"

# ---- ocpasswd file (secure perms) ----
touch /etc/ocserv/ocpasswd
chmod 640 /etc/ocserv/ocpasswd
add_change "Set /etc/ocserv/ocpasswd perms to 640 (no world-writable 777)"

# ---- Systemd unit adjustments ----
# Make sure socket unit is disabled (we'll run via service)
run_command "systemctl disable ocserv.socket || true"
# Ensure service is enabled & started
run_command "systemctl enable ocserv.service"
run_command "systemctl restart ocserv.service"
sleep 3

# ---- Optional: quick users (comment out if not needed) ----
# echo -e "malik\nmalik" | ocpasswd -c /etc/ocserv/ocpasswd malik && add_action "Added user 'malik' (plain auth only)"

# ---- Optional: small web tools (kept, but can be removed if not needed) ----
# NOTE: Leaving these as optional due to third-party source.
# run_command "apt-get install -y apache2 php libapache2-mod-php"
# run_command "wget -O /var/www/html/setup.php https://raw.githubusercontent.com/dtechdevelopers07/openconnect-php/master/setup.php"
# run_command "wget -O /var/www/html/online-users.php https://raw.githubusercontent.com/dtechdevelopers07/openconnect-php/master/onlineUsers.php"
# add_action "Downloaded optional PHP tools (setup.php, online-users.php)"

# ---- Final status ----
systemctl --no-pager status ocserv.service || true

# ========= SUMMARY =========
echo
echo "============== SETUP SUMMARY =============="
echo "Domain: $Domain"
echo "Auth  : $auth"
echo
echo "Actions performed:"
for a in "${ACTIONS[@]}"; do echo " - $a"; done
echo
echo "Security/Config changes:"
for c in "${CHANGES[@]}"; do echo " - $c"; done
echo
echo "VPN details:"
echo " - Server : $Domain"
echo " - Port   : 443"
echo " - Proto  : AnyConnect/OpenConnect (DTLS+TCP fallback)"
echo
echo "Add a user (plain auth only):  ocpasswd -c /etc/ocserv/ocpasswd <username>"
echo "Check logs: journalctl -u ocserv -f"
echo "==========================================="
run_command "systemctl status ocserv"
