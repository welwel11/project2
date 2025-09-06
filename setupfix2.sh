#!/bin/bash

# ==========================
# Auto Installer VPN Ubuntu 24
# SSHWS + Xray + HAProxy + Trojan + UDP + Vmess + Vless
# ==========================

# Color
GREEN="\e[32;1m"
YELLOW="\e[33m"
RED="\e[31m"
BLUE="\e[36m"
NC="\e[0m"

OK="${GREEN}»${NC}"
ERROR="${RED}[ERROR]${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${ERROR} Please run as root"
    exit 1
fi

# Detect OS
if ! grep -qi "ubuntu" /etc/os-release; then
    echo -e "${ERROR} Only support Ubuntu"
    exit 1
fi

# Variables
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"
IP=$(curl -sS ipv4.icanhazip.com)
DOMAIN=""
DATE=$(date +"%Y-%m-%d")
NET=$(ip route | grep default | awk '{print $5}')

clear
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  » Quick Setup VPN Server Ubuntu 24"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e " Server IP: ${GREEN}$IP${NC}"
sleep 2

# -------------------------
# Update & install base packages
# -------------------------
function base_package(){
    apt update -y
    apt upgrade -y
    apt install -y curl wget sudo zip unzip tar jq pwgen netcat socat cron bash-completion \
        gnupg lsb-release software-properties-common iptables iptables-persistent \
        dnsutils chrony vnstat fail2ban nginx haproxy dropbear openssl

    # Enable chrony
    systemctl enable chrony
    systemctl restart chrony
}

# -------------------------
# Create necessary folders
# -------------------------
function make_folder(){
    mkdir -p /etc/xray /var/log/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh
    mkdir -p /etc/bot /etc/user-create /var/www/html
    touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log
}

# -------------------------
# Domain setup
# -------------------------
function setup_domain(){
    clear
    echo -e "${YELLOW}» SETUP DOMAIN${NC}"
    echo "1) Domain Pribadi"
    echo "2) Domain Bawaan"
    read -rp "Pilih [1-2]: " choice
    if [[ "$choice" == "1" ]]; then
        read -rp "Masukkan domain/subdomain: " DOMAIN
    else
        # Install cf script
        wget -q ${REPO}files/cf.sh -O /root/cf.sh
        chmod +x /root/cf.sh
        /root/cf.sh
        DOMAIN=$(cat /root/domain)
        rm -f /root/cf.sh
    fi
    echo "$DOMAIN" > /etc/xray/domain
}

# -------------------------
# Install SSL using acme.sh
# -------------------------
function install_ssl(){
    clear
    echo -e "${OK} Installing SSL for $DOMAIN"
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $DOMAIN --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $DOMAIN \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key --ecc
    chmod 644 /etc/xray/xray.key /etc/xray/xray.crt
    print_ok "SSL Installed"
}

# -------------------------
# Install Xray Core
# -------------------------
function install_xray(){
    clear
    echo -e "${OK} Installing Xray Core"
    latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r '.[0].tag_name')
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
    # Download default config
    wget -O /etc/xray/config.json "${REPO}config/config.json"
}

# -------------------------
# SSH WebSocket
# -------------------------
function install_sshws(){
    clear
    echo -e "${OK} Installing SSH WebSocket (SSHWS)"
    wget -q -O /usr/local/bin/sshws "${REPO}files/sshws"
    chmod +x /usr/local/bin/sshws

    cat >/etc/systemd/system/sshws.service <<EOF
[Unit]
Description=SSH WebSocket Service
After=network.target

[Service]
ExecStart=/usr/local/bin/sshws
Restart=on-failure
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sshws
    systemctl start sshws
}

# -------------------------
# HAProxy & Nginx config
# -------------------------
function setup_haproxy_nginx(){
    clear
    echo -e "${OK} Setting HAProxy & Nginx"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg"
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf"
    sed -i "s/xxx/$DOMAIN/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/$DOMAIN/g" /etc/nginx/conf.d/xray.conf
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
    systemctl enable haproxy nginx
    systemctl restart haproxy nginx
}

# -------------------------
# Trojan, Vmess, Vless, Shadowsocks setup
# -------------------------
function setup_protocols(){
    mkdir -p /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks
    touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db
}

# -------------------------
# Swap & BBR
# -------------------------
function setup_swap_bbr(){
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab

    # Enable BBR
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
}

# -------------------------
# Enable & restart services
# -------------------------
function enable_services(){
    systemctl daemon-reload
    systemctl enable --now xray sshws haproxy nginx dropbear cron netfilter-persistent
    systemctl restart xray sshws haproxy nginx dropbear cron
}

# -------------------------
# Run all installation steps
# -------------------------
function main(){
    base_package
    make_folder
    setup_domain
    install_ssl
    install_xray
    install_sshws
    setup_haproxy_nginx
    setup_protocols
    setup_swap_bbr
    enable_services
    clear
    echo -e "${GREEN}✅ Installation Completed!${NC}"
    echo "Domain: $DOMAIN"
    echo "IP: $IP"
    echo "Xray, SSHWS, HAProxy, Trojan, Vmess, Vless installed."
    echo "Rebooting in 5 seconds..."
    sleep 5
    reboot
}

main