#!/bin/bash

# Warna
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
NC="\033[0m"
OK="${Green}»${NC}"
ERROR="${RED}[ERROR]${NC}"

# Bersihkan layar
clear

# Banner
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "     This Will Quick Setup VPN Server On Your Server"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# Ekspor IP
export IP=$(curl -sS https://icanhazip.com || curl -sS https://ipinfo.io/ip)

# Cek arsitektur
if [[ $(uname -m) == "x86_64" ]]; then
    echo -e "${OK} Architecture Supported: ${Green}$(uname -m)${NC}"
else
    echo -e "${ERROR} Architecture Not Supported: ${YELLOW}$(uname -m)${NC}"
    exit 1
fi

# Cek OS (hanya Ubuntu & Debian)
OS_ID=$(grep -w ID /etc/os-release | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' | xargs)
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${OK} OS Supported: ${Green}$OS_NAME${NC}"
else
    echo -e "${ERROR} OS Not Supported: ${YELLOW}$OS_NAME${NC}"
    exit 1
fi

# Cek IP
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address Not Detected"
    exit 1
else
    echo -e "${OK} IP Address: ${Green}$IP${NC}"
fi

echo ""
read -p "Press [Enter] to continue installation..."
clear

# Harus root
if [[ $EUID -ne 0 ]]; then
    echo -e "${ERROR} This script must be run as root"
    exit 1
fi

# Cek virtualisasi
if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
    echo -e "${ERROR} OpenVZ is not supported"
    exit 1
fi

# Repo
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

# Fungsi helper
print_install() {
    echo -e "${Green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}» $1${NC}"
    echo -e "${Green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${Green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${Green}» $1 successfully installed${NC}"
    echo -e "${Green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sleep 1
}

# Mulai instalasi
start=$(date +%s)

# Setup dasar (HAProxy pakai versi bawaan)
first_setup() {
    print_install "Setting up basic environment"
    timedatectl set-timezone Asia/Jakarta

    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections

    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        apt update -y && apt upgrade -y
        apt install -y haproxy nginx software-properties-common curl wget unzip sudo net-tools iptables iptables-persistent chrony vnstat openssl
    fi

    print_success "Basic Environment (HAProxy default version)"
}

# Setup Swap 1GB (khusus untuk VPS low RAM)
setup_swap() {
    print_install "Setting up Swap 1GB (recommended for 1GB RAM VPS)"
    
    if free -h | grep -q '^Swap:' && [ $(free -m | awk '/Swap:/ {print $2}') -gt 0 ]; then
        echo -e "${OK} Swap already exists ($(free -h | awk '/Swap:/ {print $3,$4}'))"
        print_success "Swap"
        return
    fi

    fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    sysctl vm.swappiness=10
    echo 'vm.swappiness=10' >> /etc/sysctl.conf
    
    echo -e "${OK} Swap 1GB berhasil dibuat dan diaktifkan"
    print_success "Swap 1GB"
}

# Enhanced iptables anti-DDoS protection
setup_ddos_protection() {
    print_install "Setting up enhanced DDoS protection (iptables rules)"

    iptables -F
    iptables -t mangle -F
    iptables -X

    iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
    iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP

    iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

    iptables -A INPUT -s 10.0.0.0/8 -j DROP
    iptables -A INPUT -s 172.16.0.0/12 -j DROP
    iptables -A INPUT -s 192.168.0.0/16 -j DROP
    iptables -A INPUT -s 169.254.0.0/16 -j DROP
    iptables -A INPUT -s 240.0.0.0/4 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP

    iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/sec --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP
    iptables -A INPUT -p tcp -m connlimit --connlimit-above 50 -j DROP

    iptables -N SYN_FLOOD
    iptables -A INPUT -p tcp --syn -j SYN_FLOOD
    iptables -A SYN_FLOOD -m limit --limit 15/sec --limit-burst 30 -j RETURN
    iptables -A SYN_FLOOD -j DROP

    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/sec -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

    netfilter-persistent save

    echo -e "${OK} Enhanced iptables DDoS protection applied"
    print_success "DDoS Protection"
}

# Direktori Xray
make_folder_xray() {
    print_install "Creating Xray directories"
    mkdir -p /etc/xray /var/log/xray /var/lib/kyt /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /etc/bot /etc/user-create
    mkdir -p /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip /etc/limit/{vmess,vless,trojan,ssh}
    touch /etc/xray/{domain,ipvps} /var/log/xray/{access.log,error.log}
    echo "$IP" > /etc/xray/ipvps
    chown -R www-data:www-data /var/log/xray
    chmod 755 /var/log/xray
    print_success "Xray Directories"
}

# Input domain
echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
echo -e "${YELLOW}» SETUP DOMAIN CLOUDFLARE ${FONT}"
echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
echo -e "  [1] Domain Pribadi"
echo -e "  [2] Domain Bawaan"
echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
read -p "  Silahkan Pilih Menu Domain 1 or 2 (enter) : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   \e[1;32mMasukan Domain Anda ! $NC"
read -p "   Subdomain: " host1
echo "IP=" >> /var/lib/kyt/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
#install cf
wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
    fi
}

clear
print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate"
}

# Install Xray Core (latest version)
install_xray() {
    print_install "Installing Latest Xray Core"
    mkdir -p /run/xray
    chown www-data:www-data /run/xray

    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data

    wget -qO /etc/xray/config.json ${REPO}config/config.json
    wget -qO /etc/systemd/system/runn.service ${REPO}files/runn.service
    wget -qO /etc/haproxy/haproxy.cfg ${REPO}config/haproxy.cfg
    wget -qO /etc/nginx/conf.d/xray.conf ${REPO}config/xray.conf
    wget -qO /etc/nginx/nginx.conf ${REPO}config/nginx.conf

    sed -i "s/xxx/$domain/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/$domain/g" /etc/nginx/conf.d/xray.conf

    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xray
    print_success "Latest Xray Core"
}

# SSH & Dropbear
setup_ssh() {
    print_install "Configuring SSH & Dropbear"
    wget -qO /etc/ssh/sshd_config ${REPO}files/sshd
    wget -qO /etc/default/dropbear ${REPO}config/dropbear.conf

    apt install -y dropbear
    systemctl restart ssh dropbear
    print_success "SSH & Dropbear"
}

# Fail2ban & Banner
setup_security() {
    print_install "Installing Fail2ban & Banner"
    apt install -y fail2ban
    systemctl enable --now fail2ban

    wget -qO /etc/kyt.txt ${REPO}files/issue.net
    echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear
    print_success "Security Features"
}

# Install menu
install_menu() {
    print_install "Installing Menu"
    wget -q ${REPO}menu/menu.zip -O /tmp/menu.zip
    unzip -o /tmp/menu.zip -d /tmp
    chmod +x /tmp/menu/*
    mv /tmp/menu/* /usr/local/sbin/
    rm -rf /tmp/menu /tmp/menu.zip

    cat > /root/.profile << 'EOF'
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
menu
EOF
    print_success "Menu Installed"
}

# Setup Auto Reboot
setup_auto_reboot() {
    print_install "Setting up Auto Reboot at 3 AM and 3 PM"
    
    cat > /etc/cron.d/auto-reboot <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * * root /sbin/reboot
0 15 * * * root /sbin/reboot
EOF

    chmod 644 /etc/cron.d/auto-reboot
    print_success "Auto Reboot (03:00 & 15:00 WIB)"
}

# Restart semua service
restart_services() {
    print_install "Restarting all services"
    systemctl restart nginx haproxy xray ssh dropbear cron vnstat fail2ban
    systemctl enable nginx haproxy xray cron netfilter-persistent
    print_success "All services restarted"
}

# Cleanup & reboot info
final_cleanup() {
    history -c
    echo "unset HISTFILE" >> /etc/profile
    rm -f /root/*.sh /root/*.zip /root/cf.sh
    echo -e "${Green}Installation completed successfully!${NC}"
    echo -e "${Green}Auto reboot telah diatur setiap jam 03:00 dan 15:00 (WIB)${NC}"
    secs_to_human $(( $(date +%s) - ${start} ))
    echo -e "Server will reboot in 10 seconds..."
    sleep 10
    reboot
}

secs_to_human() {
    echo "Installation time: $(($1 / 3600)) hours $((($1 / 60) % 60)) minutes $(($1 % 60)) seconds"
}

# Eksekusi urutan instalasi
clear
first_setup
setup_swap
setup_ddos_protection
make_folder_xray
pasang_domain
pasang_ssl
install_xray
setup_ssh
setup_security
install_menu
setup_auto_reboot
restart_services
final_cleanup