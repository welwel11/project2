#!/bin/bash
# ===================================================
# VPN Server Full Installer – Ubuntu 24+
# Features: Dropbear, SSHD, SlowDNS, vnStat, Backup,
# Swap, Fail2Ban, ePro, udp-mini, OpenVPN, Auto Reboot, Anti-DDOS, HAProxy
# ===================================================

Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'

clear
export IP=$(curl -sS icanhazip.com)

# =============================
# Basic checks
# =============================
[ "$EUID" -ne 0 ] && echo -e "${ERROR} Please run as root" && exit 1
[[ "$(systemd-detect-virt)" == "openvz" ]] && echo -e "${ERROR} OpenVZ not supported" && exit 1

ARCH=$(uname -m)
[[ "$ARCH" != "x86_64" ]] && echo -e "${ERROR} Architecture $ARCH not supported" && exit 1

OS=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
[[ "$OS" != "ubuntu" && "$OS" != "debian" ]] && echo -e "${ERROR} OS $OS not supported" && exit 1

echo -e "${OK} Architecture: $ARCH"
echo -e "${OK} OS: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo -e "${OK} IP Address: $IP"
read -p "$(echo -e "Press ${GRAY}[${NC}${Green}Enter${NC}${GRAY}]${NC} to start installation") "

# =============================
# Utility functions
# =============================
print_install() { echo -e "${YELLOW}» $1${FONT}"; sleep 1; }
print_success() { echo -e "${Green}» $1 installed${NC}"; sleep 1; }
print_error() { echo -e "${ERROR} $1"; }

# =============================
# System Setup
# =============================
first_setup() {
    timedatectl set-timezone Asia/Jakarta
    apt update -y && apt upgrade -y
    apt install -y software-properties-common unzip curl wget lsb-release net-tools
}

install_haproxy() {
    print_install "Installing HAProxy"
    apt install -y haproxy
    systemctl enable --now haproxy
    print_success "HAProxy"
}

install_nginx() {
    apt install -y nginx
    systemctl enable --now nginx
    print_success "Nginx"
}

install_base_packages() {
    apt install -y zip pwgen openssl netcat socat rclone msmtp-mta ca-certificates bsd-mailx \
        openvpn easy-rsa ruby python3-pip vnstat libsqlite3-dev
    gem install lolcat
    print_success "Base Packages"
}

# =============================
# Anti-DDoS Basic
# =============================
setup_anti_ddos() {
    print_install "Configuring basic Anti-DDoS"
    iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 5 -j REJECT
    iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT
    iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j REJECT
    iptables -A INPUT -p udp -m limit --limit 25/minute --limit-burst 50 -j ACCEPT
    iptables -A INPUT -p udp -j DROP
    netfilter-persistent save
    netfilter-persistent reload
    print_success "Anti-DDoS rules applied"
}

setup_domain() {
    read -p "Use custom domain? [y/n]: " choice
    if [[ "$choice" == "y" ]]; then
        read -p "Enter domain/subdomain: " DOMAIN
        echo "$DOMAIN" > /etc/xray/domain
    else
        wget -q https://raw.githubusercontent.com/welwel11/project2/main/files/cf.sh -O /tmp/cf.sh
        chmod +x /tmp/cf.sh && /tmp/cf.sh && rm -f /tmp/cf.sh
    fi
    print_success "Domain"
}

install_ssl() {
    DOMAIN=$(cat /etc/xray/domain)
    mkdir -p /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --issue -d $DOMAIN --standalone -k ec-256
    /root/.acme.sh/acme.sh --installcert -d $DOMAIN \
        --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 644 /etc/xray/xray.key /etc/xray/xray.crt
    print_success "SSL"
}

make_folders() {
    mkdir -p /etc/{xray,vless,vmess,trojan,shadowsocks,ssh,bot,user-create}
    mkdir -p /var/log/xray /usr/local/sbin /var/www/html /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip
    touch /etc/xray/domain /var/log/xray/{access.log,error.log}
    print_success "Directories Created"
}

install_xray() {
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.23
    wget -O /etc/xray/config.json https://raw.githubusercontent.com/welwel11/project2/main/config/config.json
    print_success "Xray"
}

install_dropbear() {
    apt install -y dropbear
    wget -O /etc/default/dropbear https://raw.githubusercontent.com/welwel11/project2/main/config/dropbear.conf
    systemctl enable --now dropbear
    print_success "Dropbear"
}

install_sshd() {
    wget -O /etc/ssh/sshd_config https://raw.githubusercontent.com/welwel11/project2/main/files/sshd
    systemctl restart ssh
    print_success "SSHD"
}

install_vnstat() {
    apt install -y vnstat libsqlite3-dev
    vnstat -u -i eth0
    systemctl enable --now vnstat
    print_success "vnStat"
}

install_udp_mini() {
    mkdir -p /usr/local/kyt
    wget -q -O /usr/local/kyt/udp-mini https://raw.githubusercontent.com/welwel11/project2/main/files/udp-mini
    chmod +x /usr/local/kyt/udp-mini
    print_success "UDP Mini"
}

install_slowdns() {
    wget -q -O /tmp/nameserver https://raw.githubusercontent.com/welwel11/project2/main/files/nameserver
    chmod +x /tmp/nameserver
    bash /tmp/nameserver
    print_success "SlowDNS"
}

install_backup() {
    apt install -y rclone
    mkdir -p /root/.config/rclone
    wget -O /root/.config/rclone/rclone.conf https://raw.githubusercontent.com/welwel11/project2/main/config/rclone.conf
    print_success "Backup"
}

install_swap() {
    dd if=/dev/zero of=/swapfile bs=1M count=1024
    mkswap /swapfile
    chmod 600 /swapfile
    swapon /swapfile
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    print_success "Swap 1GB"
}

install_fail2ban() {
    apt install -y fail2ban
    systemctl enable --now fail2ban
    print_success "Fail2Ban"
}

install_epro() {
    wget -O /usr/bin/ws https://raw.githubusercontent.com/welwel11/project2/main/files/ws
    chmod +x /usr/bin/ws
    systemctl enable --now ws
    print_success "ePro WebSocket Proxy"
}

install_openvpn() {
    apt install -y openvpn easy-rsa
    print_success "OpenVPN"
}

setup_menu() {
    wget -q https://raw.githubusercontent.com/welwel11/project2/main/menu/menu.zip -O /tmp/menu.zip
    unzip -o /tmp/menu.zip -d /usr/local/sbin
    chmod +x /usr/local/sbin/*
    rm -f /tmp/menu.zip
    print_success "Menu Installed"
}

enable_services() {
    systemctl daemon-reload
    systemctl enable --now rc-local nginx xray dropbear cron haproxy netfilter-persistent ws fail2ban
    print_success "All Services Enabled"
}

setup_auto_reboot() {
    echo "0 3 * * * root /sbin/reboot" > /etc/cron.d/auto-reboot
    print_success "Auto Reboot scheduled at 3 AM"
}

# =============================
# Installation Sequence
# =============================
clear
print_install "Starting full installation..."
first_setup
install_haproxy
install_nginx
install_base_packages
setup_anti_ddos
make_folders
setup_domain
install_ssl
install_xray
install_dropbear
install_sshd
install_vnstat
install_udp_mini
install_slowdns
install_backup
install_swap
install_fail2ban
install_epro
install_openvpn
setup_menu
enable_services
setup_auto_reboot

echo -e "${Green}Installation Completed Successfully!${NC}"
read -p "Press Enter to reboot..." && reboot
